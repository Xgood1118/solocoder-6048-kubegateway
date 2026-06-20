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
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog"

	proxyv1alpha1 "github.com/kubewharf/kubegateway/pkg/apis/proxy/v1alpha1"
	"github.com/kubewharf/kubegateway/pkg/gateway/metrics"
)

type ClusterGroup struct {
	GroupName       string
	VirtualEndpoint string
	LabelSelector   string
	PrimaryCluster  string
	BackupClusters  []string
	AutoFailover    bool

	primaryReady bool
	backupReady  map[string]bool

	mu sync.RWMutex
}

type NamespaceLabelProvider interface {
	GetNamespaceLabels(namespace string) (map[string]string, error)
}

type ClusterGroupManager struct {
	clusterManager Manager
	groups         map[string]*ClusterGroup
	virtualToGroup map[string]*ClusterGroup

	nsLabelProvider NamespaceLabelProvider

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.RWMutex
}

func NewClusterGroupManager(ctx context.Context, clusterManager Manager) *ClusterGroupManager {
	ctx, cancel := context.WithCancel(ctx)
	return &ClusterGroupManager{
		clusterManager: clusterManager,
		groups:         make(map[string]*ClusterGroup),
		virtualToGroup: make(map[string]*ClusterGroup),
		ctx:            ctx,
		cancel:         cancel,
	}
}

func (m *ClusterGroupManager) SetNamespaceLabelProvider(provider NamespaceLabelProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nsLabelProvider = provider
}

func (m *ClusterGroupManager) AddClusterGroup(config proxyv1alpha1.ClusterGroupConfig, cluster *ClusterInfo) {
	if !config.Enabled {
		return
	}

	if len(config.GroupName) == 0 || len(config.VirtualEndpoint) == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	group, exists := m.groups[config.GroupName]
	if !exists {
		group = &ClusterGroup{
			GroupName:       config.GroupName,
			VirtualEndpoint: config.VirtualEndpoint,
			LabelSelector:   config.LabelSelector,
			PrimaryCluster:  config.PrimaryCluster,
			BackupClusters:  append([]string(nil), config.BackupClusters...),
			AutoFailover:    config.AutoFailover,
			backupReady:     make(map[string]bool),
		}
		m.groups[config.GroupName] = group
		m.virtualToGroup[config.VirtualEndpoint] = group
	} else {
		group.mu.Lock()
		group.LabelSelector = config.LabelSelector
		group.PrimaryCluster = config.PrimaryCluster
		group.BackupClusters = append([]string(nil), config.BackupClusters...)
		group.AutoFailover = config.AutoFailover
		group.mu.Unlock()
	}

	group.mu.Lock()
	m.updateClusterStatusLocked(group)
	group.mu.Unlock()
}

func (m *ClusterGroupManager) RemoveClusterGroup(groupName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	group, exists := m.groups[groupName]
	if exists {
		delete(m.virtualToGroup, group.VirtualEndpoint)
		delete(m.groups, groupName)
	}
}

func (m *ClusterGroupManager) updateClusterStatusLocked(group *ClusterGroup) {
	if len(group.PrimaryCluster) > 0 {
		cluster, ok := m.clusterManager.Get(group.PrimaryCluster)
		if ok {
			group.primaryReady = m.isClusterReady(cluster)
		} else {
			group.primaryReady = false
		}
	}

	for _, backup := range group.BackupClusters {
		cluster, ok := m.clusterManager.Get(backup)
		if ok {
			group.backupReady[backup] = m.isClusterReady(cluster)
		} else {
			group.backupReady[backup] = false
		}
	}
}

func (m *ClusterGroupManager) isClusterReady(cluster *ClusterInfo) bool {
	endpoints := cluster.AllEndpoints()
	for _, ep := range endpoints {
		info, ok := cluster.Endpoints.Load(ep)
		if ok && info.IsReady() && !cluster.IsEndpointRemoved(ep) {
			return true
		}
	}
	return false
}

func (m *ClusterGroupManager) GetGroupByVirtualEndpoint(virtualEndpoint string) (*ClusterGroup, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	group, ok := m.virtualToGroup[virtualEndpoint]
	return group, ok
}

func (m *ClusterGroupManager) SelectTargetCluster(group *ClusterGroup, namespace string) (*ClusterInfo, string, error) {
	m.mu.RLock()
	provider := m.nsLabelProvider
	m.mu.RUnlock()

	group.mu.RLock()
	defer group.mu.RUnlock()

	if len(group.LabelSelector) > 0 && len(namespace) > 0 && provider != nil {
		selector, err := labels.Parse(group.LabelSelector)
		if err != nil {
			klog.Warningf("[cluster-group] failed to parse label selector %q: %v", group.LabelSelector, err)
		} else {
			nsLabels, err := provider.GetNamespaceLabels(namespace)
			if err == nil {
				if !selector.Matches(labels.Set(nsLabels)) {
					klog.V(3).Infof("[cluster-group] namespace %q labels do not match selector %q for group %q, trying backups",
						namespace, group.LabelSelector, group.GroupName)
					return m.selectBackupClusterLocked(group)
				}
			} else {
				klog.Warningf("[cluster-group] failed to get labels for namespace %q: %v", namespace, err)
			}
		}
	}

	if group.primaryReady || !group.AutoFailover {
		if len(group.PrimaryCluster) > 0 {
			cluster, ok := m.clusterManager.Get(group.PrimaryCluster)
			if ok {
				return cluster, group.PrimaryCluster, nil
			}
		}
	}

	return m.selectBackupClusterLocked(group)
}

func (m *ClusterGroupManager) selectBackupClusterLocked(group *ClusterGroup) (*ClusterInfo, string, error) {
	for _, backup := range group.BackupClusters {
		if ready, ok := group.backupReady[backup]; ok && ready {
			cluster, ok := m.clusterManager.Get(backup)
			if ok {
				klog.V(2).Infof("[cluster-group] failover to backup cluster %q for group %q", backup, group.GroupName)
				return cluster, backup, nil
			}
		}
	}

	for _, backup := range group.BackupClusters {
		cluster, ok := m.clusterManager.Get(backup)
		if ok {
			if m.isAnyEndpointReady(cluster) {
				klog.V(2).Infof("[cluster-group] using backup cluster %q (status check) for group %q", backup, group.GroupName)
				return cluster, backup, nil
			}
		}
	}

	if len(group.PrimaryCluster) > 0 {
		cluster, ok := m.clusterManager.Get(group.PrimaryCluster)
		if ok {
			return cluster, group.PrimaryCluster, nil
		}
	}

	return nil, "", fmt.Errorf("no available cluster in group %q", group.GroupName)
}

func (m *ClusterGroupManager) isAnyEndpointReady(cluster *ClusterInfo) bool {
	endpoints := cluster.AllEndpoints()
	for _, ep := range endpoints {
		info, ok := cluster.Endpoints.Load(ep)
		if ok && info.IsReady() && !cluster.IsEndpointRemoved(ep) {
			return true
		}
	}
	return false
}

func (m *ClusterGroupManager) RecordRouting(virtualEndpoint, targetCluster string) {
	metrics.RecordClusterGroupRouting(virtualEndpoint, virtualEndpoint, targetCluster)
}

func (m *ClusterGroupManager) StartHealthCheck(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.checkAllGroups()
			case <-m.ctx.Done():
				return
			}
		}
	}()
}

func (m *ClusterGroupManager) checkAllGroups() {
	m.mu.RLock()
	groups := make([]*ClusterGroup, 0, len(m.groups))
	for _, group := range m.groups {
		groups = append(groups, group)
	}
	m.mu.RUnlock()

	for _, group := range groups {
		group.mu.Lock()
		m.updateClusterStatusLocked(group)
		group.mu.Unlock()
	}
}

func (m *ClusterGroupManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *ClusterGroupManager) SyncFromClusters(clusters []*proxyv1alpha1.UpstreamCluster) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cluster := range clusters {
		if cluster.Spec.ClusterGroup.Enabled {
			ci, ok := m.clusterManager.Get(cluster.Name)
			if ok {
				m.addGroupInternal(cluster.Spec.ClusterGroup, ci)
			}
		}
	}
}

func (m *ClusterGroupManager) addGroupInternal(config proxyv1alpha1.ClusterGroupConfig, cluster *ClusterInfo) {
	if len(config.GroupName) == 0 || len(config.VirtualEndpoint) == 0 {
		return
	}

	group, exists := m.groups[config.GroupName]
	if !exists {
		group = &ClusterGroup{
			GroupName:       config.GroupName,
			VirtualEndpoint: config.VirtualEndpoint,
			LabelSelector:   config.LabelSelector,
			PrimaryCluster:  config.PrimaryCluster,
			BackupClusters:  append([]string(nil), config.BackupClusters...),
			AutoFailover:    config.AutoFailover,
			backupReady:     make(map[string]bool),
		}
		m.groups[config.GroupName] = group
		m.virtualToGroup[config.VirtualEndpoint] = group
	}

	group.mu.Lock()
	m.updateClusterStatusLocked(group)
	group.mu.Unlock()
}
