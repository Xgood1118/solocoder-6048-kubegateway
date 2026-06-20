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
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"

	proxyv1alpha1 "github.com/kubewharf/kubegateway/pkg/apis/proxy/v1alpha1"
)

type queuedRequest struct {
	priority    int32
	enqueueTime time.Time
	done        chan struct{}
	index       int
	canceled    bool
}

type priorityHeap []*queuedRequest

func (h priorityHeap) Len() int { return len(h) }
func (h priorityHeap) Less(i, j int) bool {
	if h[i].priority > h[j].priority {
		return true
	}
	if h[i].priority < h[j].priority {
		return false
	}
	return h[i].enqueueTime.Before(h[j].enqueueTime)
}
func (h priorityHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *priorityHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*queuedRequest)
	item.index = n
	*h = append(*h, item)
}

func (h *priorityHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[0 : n-1]
	return item
}

type PriorityQueueManager struct {
	cluster string
	config  proxyv1alpha1.PriorityQueueConfig

	maxInflight     int32
	currentInflight int32
	maxQueueSize    int32

	heap priorityHeap
	mu   sync.Mutex
	cond *sync.Cond

	stopCh  chan struct{}
	stopped bool

	ctx    context.Context
	cancel context.CancelFunc

	priorityRules   []proxyv1alpha1.PriorityRule
	defaultPriority int32

	degradedCache map[string]cachedResponse
	cacheMu       sync.RWMutex
}

type cachedResponse struct {
	data        []byte
	contentType string
	timestamp   time.Time
}

func NewPriorityQueueManager(ctx context.Context, cluster string, config proxyv1alpha1.PriorityQueueConfig, maxInflight int32) *PriorityQueueManager {
	ctx, cancel := context.WithCancel(ctx)

	mgr := &PriorityQueueManager{
		cluster:         cluster,
		config:          config,
		maxInflight:     maxInflight,
		maxQueueSize:    config.MaxQueueSize,
		heap:            make(priorityHeap, 0),
		stopCh:          make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
		priorityRules:   config.PriorityRules,
		defaultPriority: config.DefaultPriority,
		degradedCache:   make(map[string]cachedResponse),
	}

	if mgr.maxQueueSize <= 0 {
		mgr.maxQueueSize = 1000
	}
	if mgr.defaultPriority <= 0 {
		mgr.defaultPriority = 5
	}

	mgr.cond = sync.NewCond(&mgr.mu)

	heap.Init(&mgr.heap)

	return mgr
}

func (p *PriorityQueueManager) GetPriority(verb, apiGroup, resource string) int32 {
	for _, rule := range p.priorityRules {
		if matchesPriorityRule(rule, verb, apiGroup, resource) {
			return rule.Priority
		}
	}
	return p.defaultPriority
}

func matchesPriorityRule(rule proxyv1alpha1.PriorityRule, verb, apiGroup, resource string) bool {
	verbMatch := false
	for _, v := range rule.Verbs {
		if v == "*" || v == verb {
			verbMatch = true
			break
		}
	}
	if !verbMatch && len(rule.Verbs) > 0 {
		return false
	}

	groupMatch := false
	for _, g := range rule.APIGroups {
		if g == "*" || g == apiGroup {
			groupMatch = true
			break
		}
	}
	if !groupMatch && len(rule.APIGroups) > 0 {
		return false
	}

	resourceMatch := false
	for _, r := range rule.Resources {
		if r == "*" || r == resource {
			resourceMatch = true
			break
		}
	}
	if !resourceMatch && len(rule.Resources) > 0 {
		return false
	}

	return true
}

func (p *PriorityQueueManager) TryAcquire(priority int32, maxWait time.Duration) (bool, time.Duration, error) {
	startTime := time.Now()

	p.mu.Lock()

	if p.stopped {
		p.mu.Unlock()
		return false, 0, fmt.Errorf("priority queue is stopped")
	}

	if p.currentInflight < p.maxInflight {
		p.currentInflight++
		p.mu.Unlock()
		return true, 0, nil
	}

	if int32(p.heap.Len()) >= p.maxQueueSize {
		p.mu.Unlock()
		return false, 0, errors.NewTooManyRequests(fmt.Sprintf("priority queue is full"), 0)
	}

	req := &queuedRequest{
		priority:    priority,
		enqueueTime: time.Now(),
		done:        make(chan struct{}),
	}
	heap.Push(&p.heap, req)
	p.mu.Unlock()

	timeout := time.After(maxWait)
	select {
	case <-req.done:
		waitDuration := time.Since(startTime)
		return true, waitDuration, nil
	case <-timeout:
		p.mu.Lock()
		req.canceled = true
		if req.index >= 0 {
			heap.Remove(&p.heap, req.index)
		}
		p.mu.Unlock()
		return false, time.Since(startTime), errors.NewTimeoutError("request timeout in priority queue", 0)
	case <-p.ctx.Done():
		return false, time.Since(startTime), p.ctx.Err()
	case <-p.stopCh:
		return false, time.Since(startTime), fmt.Errorf("priority queue stopped")
	}
}

func (p *PriorityQueueManager) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.currentInflight--

	if p.currentInflight < 0 {
		p.currentInflight = 0
	}

	if p.heap.Len() > 0 && p.currentInflight < p.maxInflight {
		item := heap.Pop(&p.heap).(*queuedRequest)
		if !item.canceled {
			p.currentInflight++
			close(item.done)
		} else {
			for p.heap.Len() > 0 {
				next := heap.Pop(&p.heap).(*queuedRequest)
				if !next.canceled {
					p.currentInflight++
					close(next.done)
					break
				}
			}
		}
	}
}

func (p *PriorityQueueManager) UpdateConfig(config proxyv1alpha1.PriorityQueueConfig, maxInflight int32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config
	p.maxInflight = maxInflight
	p.priorityRules = config.PriorityRules
	p.defaultPriority = config.DefaultPriority
	if p.defaultPriority <= 0 {
		p.defaultPriority = 5
	}
	if config.MaxQueueSize > 0 {
		p.maxQueueSize = config.MaxQueueSize
	}
}

func (p *PriorityQueueManager) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}

	p.stopped = true
	close(p.stopCh)
	p.cancel()

	for p.heap.Len() > 0 {
		req := heap.Pop(&p.heap).(*queuedRequest)
		close(req.done)
	}
}

func (p *PriorityQueueManager) CurrentInflight() int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentInflight
}

func (p *PriorityQueueManager) QueueSize() int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return int32(p.heap.Len())
}

func (p *PriorityQueueManager) SetCachedResponse(key string, data []byte, contentType string) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	p.degradedCache[key] = cachedResponse{
		data:        data,
		contentType: contentType,
		timestamp:   time.Now(),
	}
}

func (p *PriorityQueueManager) GetCachedResponse(key string) ([]byte, string, bool) {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()

	cached, ok := p.degradedCache[key]
	if !ok {
		return nil, "", false
	}

	if time.Since(cached.timestamp) > 5*time.Minute {
		return nil, "", false
	}

	return cached.data, cached.contentType, true
}

func (p *PriorityQueueManager) ShouldDegrade(priority int32) bool {
	if !p.config.EnableDegradedResponse {
		return false
	}
	threshold := p.config.DegradedPriorityThreshold
	if threshold <= 0 {
		threshold = 3
	}
	return priority <= threshold
}

func (p *PriorityQueueManager) IsOverloaded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentInflight >= p.maxInflight && p.heap.Len() > 0
}

func RecordDegradedResponse(key string) {
	klog.V(4).Infof("[priority-queue] returning degraded response for %s", key)
}
