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

package clusters

import (
	"context"
	"sort"
	"sync"
	"time"

	"k8s.io/klog"

	proxyv1alpha1 "github.com/kubewharf/kubegateway/pkg/apis/proxy/v1alpha1"
	"github.com/kubewharf/kubegateway/pkg/gateway/metrics"
)

type latencySample struct {
	latency   time.Duration
	success   bool
	timestamp time.Time
}

type endpointWeightState struct {
	endpoint string

	currentWeight int32
	baseWeight    int32

	latencyWindow []latencySample
	windowSize    int
	windowIndex   int

	consecutiveFailures int32
	failureThreshold    int32

	removed        bool
	removedAt      time.Time
	backoffSeconds int32
	baseBackoff    int32
	maxBackoff     int32
	nextRetryAt    time.Time

	mu sync.RWMutex
}

func newEndpointWeightState(endpoint string, baseWeight int32, config proxyv1alpha1.AdaptiveWeightConfig) *endpointWeightState {
	windowSize := int(config.WindowSize)
	if windowSize <= 0 {
		windowSize = 100
	}

	failureThreshold := config.FailureThreshold
	if failureThreshold <= 0 {
		failureThreshold = 5
	}

	baseBackoff := config.BaseBackoffSeconds
	if baseBackoff <= 0 {
		baseBackoff = 1
	}

	maxBackoff := config.MaxBackoffSeconds
	if maxBackoff <= 0 {
		maxBackoff = 300
	}

	minWeight := config.MinWeight
	if minWeight <= 0 {
		minWeight = 1
	}
	if baseWeight < minWeight {
		baseWeight = minWeight
	}

	return &endpointWeightState{
		endpoint:         endpoint,
		currentWeight:    baseWeight,
		baseWeight:       baseWeight,
		latencyWindow:    make([]latencySample, windowSize),
		windowSize:       windowSize,
		failureThreshold: failureThreshold,
		baseBackoff:      baseBackoff,
		maxBackoff:       maxBackoff,
		backoffSeconds:   baseBackoff,
	}
}

func (w *endpointWeightState) RecordLatency(latency time.Duration, success bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	sample := latencySample{
		latency:   latency,
		success:   success,
		timestamp: time.Now(),
	}

	w.latencyWindow[w.windowIndex] = sample
	w.windowIndex = (w.windowIndex + 1) % w.windowSize

	if success {
		w.consecutiveFailures = 0
		if w.removed && time.Now().After(w.nextRetryAt) {
			w.removed = false
			w.backoffSeconds = w.baseBackoff
			klog.V(2).Infof("[adaptive-weight] endpoint %s recovered from removal", w.endpoint)
			metrics.RecordUpstreamRecovered(w.endpoint, w.endpoint)
		}
	} else {
		w.consecutiveFailures++
		if w.consecutiveFailures >= w.failureThreshold && !w.removed {
			w.removed = true
			w.removedAt = time.Now()
			w.nextRetryAt = time.Now().Add(time.Duration(w.backoffSeconds) * time.Second)
			klog.Warningf("[adaptive-weight] endpoint %s removed due to %d consecutive failures, backoff %ds",
				w.endpoint, w.consecutiveFailures, w.backoffSeconds)
			metrics.RecordUpstreamRemoved(w.endpoint, w.endpoint, "consecutive_failures")
		}
	}
}

func (w *endpointWeightState) p99LatencyLocked() time.Duration {
	latencies := make([]time.Duration, 0, w.windowSize)
	for i := 0; i < w.windowSize; i++ {
		idx := (w.windowIndex + i) % w.windowSize
		if w.latencyWindow[idx].success && w.latencyWindow[idx].timestamp.After(time.Time{}) {
			latencies = append(latencies, w.latencyWindow[idx].latency)
		}
	}

	if len(latencies) == 0 {
		return 0
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	p99Index := int(float64(len(latencies)) * 0.99)
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}
	return latencies[p99Index]
}

func (w *endpointWeightState) P99Latency() time.Duration {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.p99LatencyLocked()
}

func (w *endpointWeightState) GetWeight() int32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.removed {
		return 0
	}
	return w.currentWeight
}

func (w *endpointWeightState) IsRemoved() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.removed
}

func (w *endpointWeightState) AdjustWeight(minWeight, maxWeight int32, avgP99 time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.removed {
		if time.Now().After(w.nextRetryAt) {
			w.removed = false
			w.backoffSeconds = w.baseBackoff
			klog.V(2).Infof("[adaptive-weight] endpoint %s re-added after backoff", w.endpoint)
			metrics.RecordUpstreamRecovered(w.endpoint, w.endpoint)
		} else {
			return
		}
	}

	p99 := w.p99LatencyLocked()
	if p99 == 0 {
		return
	}

	if avgP99 == 0 {
		return
	}

	ratio := float64(p99) / float64(avgP99)
	newWeight := int32(float64(w.baseWeight) / ratio)

	if newWeight < minWeight {
		newWeight = minWeight
	}
	if newWeight > maxWeight {
		newWeight = maxWeight
	}

	if newWeight != w.currentWeight {
		klog.V(3).Infof("[adaptive-weight] endpoint %s weight adjusted: %d -> %d (p99=%v, avg_p99=%v, ratio=%.2f)",
			w.endpoint, w.currentWeight, newWeight, p99, avgP99, ratio)
		w.currentWeight = newWeight
	}
}

func (w *endpointWeightState) TryRestoreAfterBackoff() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.removed {
		return false
	}

	if time.Now().After(w.nextRetryAt) {
		w.removed = false
		w.backoffSeconds *= 2
		if w.backoffSeconds > w.maxBackoff {
			w.backoffSeconds = w.maxBackoff
		}
		w.nextRetryAt = time.Now().Add(time.Duration(w.backoffSeconds) * time.Second)
		w.consecutiveFailures = 0
		klog.V(2).Infof("[adaptive-weight] endpoint %s retry after backoff, next retry at %v", w.endpoint, w.nextRetryAt)
		return true
	}
	return false
}

type adaptiveWeightManager struct {
	cluster   string
	config    proxyv1alpha1.AdaptiveWeightConfig
	weights   map[string]*endpointWeightState
	minWeight int32
	maxWeight int32

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.RWMutex
}

func newAdaptiveWeightManager(ctx context.Context, cluster string, config proxyv1alpha1.AdaptiveWeightConfig, endpoints []string, baseWeights map[string]int32) *adaptiveWeightManager {
	ctx, cancel := context.WithCancel(ctx)

	minWeight := config.MinWeight
	if minWeight <= 0 {
		minWeight = 1
	}
	maxWeight := config.MaxWeight
	if maxWeight <= 0 {
		maxWeight = 100
	}

	mgr := &adaptiveWeightManager{
		cluster:   cluster,
		config:    config,
		weights:   make(map[string]*endpointWeightState),
		minWeight: minWeight,
		maxWeight: maxWeight,
		ctx:       ctx,
		cancel:    cancel,
	}

	for _, ep := range endpoints {
		baseWeight := int32(10)
		if bw, ok := baseWeights[ep]; ok && bw > 0 {
			baseWeight = bw
		}
		mgr.weights[ep] = newEndpointWeightState(ep, baseWeight, config)
	}

	return mgr
}

func (m *adaptiveWeightManager) RecordLatency(endpoint string, latency time.Duration, success bool) {
	m.mu.RLock()
	ws, ok := m.weights[endpoint]
	m.mu.RUnlock()

	if !ok {
		return
	}
	ws.RecordLatency(latency, success)
}

func (m *adaptiveWeightManager) GetWeight(endpoint string) int32 {
	m.mu.RLock()
	ws, ok := m.weights[endpoint]
	m.mu.RUnlock()

	if !ok {
		return 0
	}
	return ws.GetWeight()
}

func (m *adaptiveWeightManager) IsRemoved(endpoint string) bool {
	m.mu.RLock()
	ws, ok := m.weights[endpoint]
	m.mu.RUnlock()

	if !ok {
		return true
	}
	return ws.IsRemoved()
}

func (m *adaptiveWeightManager) GetAllWeights() map[string]int32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]int32, len(m.weights))
	for ep, ws := range m.weights {
		result[ep] = ws.GetWeight()
	}
	return result
}

func (m *adaptiveWeightManager) AdjustWeights() {
	m.mu.RLock()
	weightStates := make([]*endpointWeightState, 0, len(m.weights))
	for _, ws := range m.weights {
		weightStates = append(weightStates, ws)
	}
	minWeight := m.minWeight
	maxWeight := m.maxWeight
	m.mu.RUnlock()

	var totalP99 time.Duration
	var count int
	p99Values := make([]time.Duration, len(weightStates))
	for i, ws := range weightStates {
		if !ws.IsRemoved() {
			p99 := ws.P99Latency()
			p99Values[i] = p99
			if p99 > 0 {
				totalP99 += p99
				count++
			}
		}
	}

	if count == 0 {
		return
	}

	avgP99 := totalP99 / time.Duration(count)

	for _, ws := range weightStates {
		ws.AdjustWeight(minWeight, maxWeight, avgP99)
	}
}

func (m *adaptiveWeightManager) Start(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.AdjustWeights()
				m.reportMetrics()
			case <-m.ctx.Done():
				return
			}
		}
	}()
}

func (m *adaptiveWeightManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *adaptiveWeightManager) reportMetrics() {
	weights := m.GetAllWeights()
	for ep, weight := range weights {
		metrics.RecordUpstreamWeight(m.cluster, ep, float64(weight))
	}
}

func (m *adaptiveWeightManager) AddEndpoint(endpoint string, baseWeight int32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.weights[endpoint]; ok {
		return
	}

	if baseWeight <= 0 {
		baseWeight = 10
	}

	m.weights[endpoint] = newEndpointWeightState(endpoint, baseWeight, m.config)
}

func (m *adaptiveWeightManager) RemoveEndpoint(endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.weights, endpoint)
}

func (m *adaptiveWeightManager) UpdateConfig(config proxyv1alpha1.AdaptiveWeightConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = config

	if config.MinWeight > 0 {
		m.minWeight = config.MinWeight
	}
	if config.MaxWeight > 0 {
		m.maxWeight = config.MaxWeight
	}
}
