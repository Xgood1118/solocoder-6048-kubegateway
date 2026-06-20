// Copyright 2022 ByteDance and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dispatcher

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gobeam/stringy"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/endpoints/filters"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/kubewharf/kubegateway/pkg/clusters"
	"github.com/kubewharf/kubegateway/pkg/gateway/endpoints/request"
	"github.com/kubewharf/kubegateway/pkg/gateway/endpoints/response"
	"github.com/kubewharf/kubegateway/pkg/gateway/metrics"
	"github.com/kubewharf/kubegateway/pkg/util/tracing"
)

type dispatcher struct {
	clusters.Manager
	codecs          serializer.CodecFactory
	enableAccessLog bool
}

func NewDispatcher(clusterManager clusters.Manager, enableAccessLog bool) http.Handler {
	return &dispatcher{
		Manager:         clusterManager,
		codecs:          scheme.Codecs,
		enableAccessLog: enableAccessLog,
	}
}

// TODO: add metrics
func (d *dispatcher) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	tracing.Step(ctx, tracing.StepDispatcher)

	user, ok := genericapirequest.UserFrom(ctx)
	if !ok {
		d.responseError(errors.NewInternalError(fmt.Errorf("no user info found in request context")), w, req, statusReasonInvalidRequestContext)
		return
	}
	extraInfo, ok := request.ExtraRequestInfoFrom(ctx)
	if !ok {
		d.responseError(errors.NewInternalError(fmt.Errorf("no extra request info found in request context")), w, req, statusReasonInvalidRequestContext)
		return
	}
	requestInfo, ok := genericapirequest.RequestInfoFrom(ctx)
	if !ok {
		d.responseError(errors.NewInternalError(fmt.Errorf("no request info found in request context")), w, req, statusReasonInvalidRequestContext)
		return
	}
	cluster := extraInfo.UpstreamCluster
	if extraInfo.IsProxyRequest && cluster == nil {
		d.responseError(errors.NewServiceUnavailable(fmt.Sprintf("the request cluster(%s) is not being proxied", extraInfo.Hostname)), w, req, statusReasonClusterNotBeingProxied)
		return
	}

	requestAttributes, err := filters.GetAuthorizerAttributes(ctx)
	if err != nil {
		d.responseError(errors.NewInternalError(err), w, req, statusReasonInvalidRequestContext)
		return
	}
	endpointPicker, err := cluster.MatchAttributes(requestAttributes)
	if err != nil {
		d.responseError(errors.NewInternalError(err), w, req, normalizeErrToReason(err))
		return
	}

	_ = request.SetProxyInfo(req.Context(), endpointPicker.FlowControlName(), user)

	flowcontrol := endpointPicker.FlowControl()
	if !flowcontrol.TryAcquire() {
		//TODO: exempt master request and long running request
		// add metrics
		retryAfter := 0
		if requestAttributes.GetResource() != "events" {
			retryAfter = response.RetryAfter
		}
		d.responseError(errors.NewTooManyRequests(fmt.Sprintf("too many requests for cluster(%s), limited by flowControl(%v)", extraInfo.Hostname, flowcontrol.String()), retryAfter), w, req, statusReasonRateLimited)
		return
	}
	defer flowcontrol.Release()

	priorityQueue := cluster.PriorityQueueManager()
	var waitDuration time.Duration
	if priorityQueue != nil {
		priority := cluster.GetRequestPriority(
			requestAttributes.GetVerb(),
			requestAttributes.GetAPIGroup(),
			requestAttributes.GetResource(),
		)

		maxWait := 30 * time.Second

		acquired, waitDur, err := priorityQueue.TryAcquire(priority, maxWait)
		waitDuration = waitDur

		w.Header().Set("X-KubeGateway-Queue-Wait", fmt.Sprintf("%.3fms", float64(waitDuration.Microseconds())/1000.0))
		w.Header().Set("X-KubeGateway-Priority", fmt.Sprintf("%d", priority))

		if waitDuration > 0 {
			metrics.RecordPriorityQueueWait(extraInfo.Hostname, "", fmt.Sprintf("%d", priority), waitDuration)
		}

		if !acquired {
			if priorityQueue.ShouldDegrade(priority) && priorityQueue.IsOverloaded() {
				cacheKey := fmt.Sprintf("%s:%s:%s", requestAttributes.GetVerb(), requestAttributes.GetAPIGroup(), requestAttributes.GetResource())
				if data, contentType, ok := priorityQueue.GetCachedResponse(cacheKey); ok {
					w.Header().Set("Content-Type", contentType)
					w.Header().Set("X-KubeGateway-Degraded", "true")
					w.WriteHeader(http.StatusOK)
					w.Write(data)
					return
				}
			}
			if err != nil {
				if errStatus, ok := err.(*errors.StatusError); ok {
					d.responseError(errStatus, w, req, statusReasonRateLimited)
				} else {
					d.responseError(errors.NewServiceUnavailable(err.Error()), w, req, statusReasonNoReadyEndpoints)
				}
			}
			return
		}
		defer priorityQueue.Release()
	}

	endpoint, err := endpointPicker.Pop()
	if err != nil {
		d.responseError(errors.NewServiceUnavailable(err.Error()), w, req, statusReasonNoReadyEndpoints)
		return
	}

	ep, err := url.Parse(endpoint.Endpoint)
	if err != nil {
		d.responseError(errors.NewInternalError(err), w, req, statusReasonInvalidEndpoint)
		return
	}

	// mark this proxy request forwarded
	if err := request.SetProxyForwarded(req.Context(), endpoint.Endpoint); err != nil {
		d.responseError(errors.NewInternalError(err), w, req, statusReasonInvalidRequestContext)
		return
	}

	location := &url.URL{}
	location.Scheme = ep.Scheme
	location.Host = ep.Host
	location.Path = req.URL.Path
	location.RawQuery = req.URL.Query().Encode()

	newReq, cancel := newRequestForProxy(location, req, extraInfo.Hostname)
	// close this request if endpoint is stoped
	go func() {
		select {
		case <-newReq.Context().Done():
			// this context comes from incoming server requests, and then we use
			// it as proxy client context to control cancellation
			//
			// For incoming server requests, the context is canceled when the
			// client's connection closes, the request is canceled (with HTTP/2),
			// or when the ServeHTTP method returns.
		case <-endpoint.Context().Done():
			// when endpoint stopping, we should cancel the context to close proxy request
			cancel()
		}
	}()

	logging := d.enableAccessLog && endpointPicker.EnableLog()
	monitor := requestMonitor(req, w, logging, requestInfo, extraInfo, endpoint.Endpoint, user, extraInfo.Impersonator, endpointPicker.FlowControlName())
	monitor.MonitorBeforeProxy()
	startTime := time.Now()

	defer func() {
		monitor.MonitorAfterProxy()
		elapsed := time.Since(startTime)
		success := true
		if extraInfo.ReaderWriter != nil {
			status := extraInfo.ReaderWriter.Status()
			if status >= 500 || status == 0 {
				success = false
			}
		}
		if cluster != nil {
			cluster.RecordEndpointLatency(endpoint.Endpoint, elapsed, success)
		}
	}()

	responder := newErrorResponder(d.codecs, endpoint, requestInfo, extraInfo.ReaderWriter)

	proxyHandler := NewUpgradeAwareHandler(location, endpoint.ProxyTransport, endpoint.PorxyUpgradeTransport, false, false, responder)
	proxyHandler.ServeHTTP(w, newReq)
}

func (d *dispatcher) responseError(err *errors.StatusError, w http.ResponseWriter, req *http.Request, reason string) {
	responseError(d.codecs, err, w, req, reason)
}

// newRequestForProxy returns a shallow copy of the original request with a context that may include a timeout for discovery requests
func newRequestForProxy(location *url.URL, req *http.Request, _ string) (*http.Request, context.CancelFunc) {
	ctx := req.Context()
	newCtx, cancel := context.WithCancel(ctx)

	// WithContext creates a shallow clone of the request with the same context.
	newReq := req.WithContext(newCtx)
	newReq.Header = utilnet.CloneHeader(req.Header)
	newReq.URL = location

	return newReq, cancel
}

func normalizeErrToReason(err error) string {
	str := stringy.New(err.Error())
	return str.SnakeCase().ToLower()
}
