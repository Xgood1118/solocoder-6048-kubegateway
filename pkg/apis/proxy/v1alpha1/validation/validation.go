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

package validation

import (
	"crypto/tls"
	"fmt"
	"strings"

	apimachineryvalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	certutil "k8s.io/client-go/util/cert"
	apivalidation "k8s.io/kubernetes/pkg/apis/core/validation"

	proxyv1alpha1 "github.com/kubewharf/kubegateway/pkg/apis/proxy/v1alpha1"
)

func ValidateUpstreamCluster(cluster *proxyv1alpha1.UpstreamCluster) field.ErrorList {
	allErrs := apivalidation.ValidateObjectMeta(&cluster.ObjectMeta, false, apimachineryvalidation.NameIsDNSSubdomain, field.NewPath("metadata"))
	allErrs = append(allErrs, ValidateUpstreamClusterSpec(&cluster.Spec, field.NewPath("spec"))...)
	return allErrs
}

// ValidateUpstreamClusterSpec tests if required fields in the UpstreamCluster spec are set.
func ValidateUpstreamClusterSpec(spec *proxyv1alpha1.UpstreamClusterSpec, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	upstreams, scheme, errs := ValidateServers(spec.Servers, fldPath.Child("servers"))

	allErrs = append(allErrs, errs...)
	allErrs = append(allErrs, ValidateClientConfig(scheme, &spec.ClientConfig, fldPath.Child("clientConfig"))...)
	allErrs = append(allErrs, ValidateSecureServing(&spec.SecureServing, fldPath.Child("secureServing"))...)

	flowControlSchemaNames, errs := ValidateFlowControl(&spec.FlowControl, fldPath.Child("flowControl"))
	allErrs = append(allErrs, errs...)
	allErrs = append(allErrs, ValidateLoggingConfig(spec.Logging, fldPath.Child("logging"))...)

	if len(spec.DispatchPolicies) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("dispatchPolicies"), "resource must supply at least one dispatch policy"))
	}
	for i, policy := range spec.DispatchPolicies {
		allErrs = append(allErrs, ValidateDispatchPolicy(upstreams, flowControlSchemaNames, policy, fldPath.Child("dispatchPolicies").Index(i))...)
	}

	allErrs = append(allErrs, ValidateAdaptiveWeightConfig(&spec.AdaptiveWeight, fldPath.Child("adaptiveWeight"))...)
	allErrs = append(allErrs, ValidatePriorityQueueConfig(&spec.PriorityQueue, fldPath.Child("priorityQueue"))...)
	allErrs = append(allErrs, ValidateClusterGroupConfig(&spec.ClusterGroup, fldPath.Child("clusterGroup"))...)

	return allErrs
}

func ValidateServers(servers []proxyv1alpha1.UpstreamClusterServer, fldPath *field.Path) (sets.String, string, field.ErrorList) {
	allErrs := field.ErrorList{}

	upstreams := sets.NewString()
	if len(servers) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("servers"), "resource must supply at least one upstream server"))
	}

	schemes := sets.NewString()
	for i, s := range servers {
		scheme := getURLScheme(servers[i].Endpoint)
		if len(scheme) == 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("servers").Index(i), s, "endpoint must supply http(s) schema"))
		} else {
			schemes.Insert(scheme)
		}
		upstreams.Insert(s.Endpoint)
	}

	if schemes.Len() > 1 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("servers"), "", "all upstream servers' endpoints must use the same scheme"))
	}

	scheme, _ := schemes.PopAny()
	return upstreams, scheme, allErrs
}

func ValidateClientConfig(scheme string, clientconfig *proxyv1alpha1.ClientConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if clientconfig.QPS < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("qps"), "", "qps must be bigger than or equal to 0"))
	}
	if clientconfig.Burst < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("burst"), "", "burst must be bigger than or equal to 0"))
	}
	if clientconfig.QPSDivisor < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("qpsDivisor"), "", "qpsDivisor must be bigger than or equal to 0"))
	}
	if clientconfig.QPS > 0 && clientconfig.Burst < clientconfig.QPS {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("burst"), "", "burst must be bigger than qps when qps is not equal to 0"))
	}

	if scheme == "https" {
		if !clientconfig.Insecure && len(clientconfig.CAData) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("caData"), "clientConfig must supply caData when using secure mode"))
		}

		var hasToken, hasKey, hasCert bool
		if len(clientconfig.BearerToken) > 0 {
			hasToken = true
		}
		if len(clientconfig.KeyData) > 0 {
			hasKey = true
		}
		if len(clientconfig.CertData) > 0 {
			hasCert = true
		}

		if !hasToken && !hasKey && !hasCert {
			allErrs = append(allErrs, &field.Error{Type: field.ErrorTypeRequired, Field: "spec.clientConfig", Detail: "clientConfig must supply at least one user authentication when endpoint schema is HTTPS"})
		} else {
			if hasKey || hasCert {
				if !hasKey {
					allErrs = append(allErrs, field.Required(fldPath.Child("keyData"), "clientConfig must supply at least one user authentication when endpoint schema is HTTPS"))
				}
				if !hasCert {
					allErrs = append(allErrs, field.Required(fldPath.Child("certData"), "clientConfig must supply at least one user authentication when endpoint schema is HTTPS"))
				}
			} else {
				if !hasToken {
					allErrs = append(allErrs, field.Required(fldPath.Child("bearerToken"), "clientConfig must supply at least one user authentication when endpoint schema is HTTPS"))
				}
			}
		}
	}

	if len(clientconfig.KeyData) > 0 && len(clientconfig.CertData) > 0 {
		_, err := tls.X509KeyPair(clientconfig.CertData, clientconfig.KeyData)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("certData"), string(clientconfig.CertData), "cluster client CertData invalid:"+err.Error()))
			allErrs = append(allErrs, field.Invalid(fldPath.Child("keyData"), string(clientconfig.KeyData), "cluster client KeyData invalid:"+err.Error()))
		}
	}

	// validate server ca
	if len(clientconfig.CAData) > 0 {
		_, err := certutil.ParseCertsPEM(clientconfig.CAData)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec.ClientConfig.CAData"), string(clientconfig.CAData), "cluster client CAData invalid:"+err.Error()))
		}
	}

	return allErrs
}

func ValidateSecureServing(serving *proxyv1alpha1.SecureServing, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(serving.CertData) > 0 && len(serving.KeyData) > 0 {
		_, err := tls.X509KeyPair(serving.CertData, serving.KeyData)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("certData"), string(serving.CertData), "cluster secure serving CertData invalid:"+err.Error()))
			allErrs = append(allErrs, field.Invalid(fldPath.Child("keyData"), string(serving.KeyData), "cluster secure serving KeyData invalid:"+err.Error()))
		}
	}

	if len(serving.ClientCAData) > 0 {
		_, err := certutil.ParseCertsPEM(serving.ClientCAData)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("clientCAData"), string(serving.ClientCAData), "cluster secure serving ClientCAData invalid:"+err.Error()))
		}
	}

	return allErrs
}

func ValidateFlowControl(flowcontrol *proxyv1alpha1.FlowControl, fldPath *field.Path) (sets.String, field.ErrorList) {
	flowControlSchemaNames := sets.NewString()

	allErrs := field.ErrorList{}
	flowControlFieldPath := fldPath.Child("flowControlSchemas")
	for i := range flowcontrol.Schemas {
		fs := flowcontrol.Schemas[i]
		if len(fs.Name) == 0 {
			allErrs = append(allErrs, field.Required(flowControlFieldPath.Index(i).Child("name"), fs.Name))
		} else if flowControlSchemaNames.Has(fs.Name) {
			allErrs = append(allErrs, field.Duplicate(flowControlFieldPath.Index(i).Child("name"), fs.Name))
		} else {
			flowControlSchemaNames.Insert(fs.Name)
		}

		switch fs.Strategy {
		case proxyv1alpha1.LocalLimit, proxyv1alpha1.GlobalAllocateLimit, proxyv1alpha1.GlobalCountLimit, "":
		default:
			allErrs = append(allErrs, field.Invalid(flowControlFieldPath.Index(i).Child("strategy"), fs.Strategy, fmt.Sprintf("valid value: must be of of %v",
				[]proxyv1alpha1.LimitStrategy{proxyv1alpha1.LocalLimit, proxyv1alpha1.GlobalAllocateLimit, proxyv1alpha1.GlobalCountLimit, "\"\""})))
		}

		allErrs = append(allErrs, ValidateFlowControlConfiguration(&fs.FlowControlSchemaConfiguration, flowControlFieldPath.Index(i))...)
	}

	return flowControlSchemaNames, allErrs
}

func ValidateLoggingConfig(logging proxyv1alpha1.LoggingConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	switch logging.Mode {
	case proxyv1alpha1.LogOff, proxyv1alpha1.LogOn, "":
	default:
		allErrs = append(allErrs, field.Invalid(fldPath.Child("mode"), logging.Mode, "valid value: on or off"))
	}
	return allErrs
}

func ValidateDispatchPolicy(upstreams, flowControlSchemaNames sets.String, policy proxyv1alpha1.DispatchPolicy, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	switch policy.Strategy {
	case proxyv1alpha1.RoundRobin:
	default:
		allErrs = append(allErrs, field.Invalid(fldPath.Child("strategy"), policy.Strategy, ""))
	}

	for j, u := range policy.UpstreamSubset {
		if !upstreams.Has(u) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("upstreamSubset").Index(j), u, "upstream subset endpoint must be present in servers"))
		}
	}

	if len(policy.FlowControlSchemaName) > 0 && !flowControlSchemaNames.Has(policy.FlowControlSchemaName) {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("flowControlSchemaName"), policy.FlowControlSchemaName, "policy's flowControlSchema name must be present in FlowControlShcemas"))
	}

	if len(policy.Rules) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("rules"), "dispatch policy must supply at least one rule"))
	}

	switch policy.LogMode {
	case proxyv1alpha1.LogOff, proxyv1alpha1.LogOn, "":
	default:
		allErrs = append(allErrs, field.Invalid(fldPath.Child("mode"), policy.LogMode, "valid value: on or off"))
	}
	return allErrs
}

func ValidateRule(rule proxyv1alpha1.DispatchPolicyRule, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if len(rule.Verbs) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("verbs"), "verbs must contain at least one value"))
	}

	if len(rule.NonResourceURLs) > 0 {
		return allErrs
	}

	if len(rule.APIGroups) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("apiGroups"), "resource rules must supply at least one api group"))
	}
	if len(rule.Resources) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("resources"), "resource rules must supply at least one resource"))
	}
	for i, r := range rule.Resources {
		if strings.HasSuffix(r, "/*") {
			allErrs = append(allErrs, field.Required(fldPath.Child("resources").Index(i), "rules must not match all subresources of resource"))
		}
	}

	return allErrs
}

func getURLScheme(server string) string {
	if strings.HasPrefix(server, "http://") {
		return "http"
	} else if strings.HasPrefix(server, "https://") {
		return "https"
	}
	return ""
}

func ValidateFlowControlConfiguration(schema *proxyv1alpha1.FlowControlSchemaConfiguration, fldPath *field.Path) field.ErrorList {
	numConfig := 0
	allErrs := field.ErrorList{}

	if schema.Exempt != nil {
		numConfig++
	}
	if schema.MaxRequestsInflight != nil {
		if numConfig > 0 {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("maxRequestsInflight"), "may not specify more than 1 flow control configuration"))
		} else {
			numConfig++
			if schema.MaxRequestsInflight.Max < 0 {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("maxRequestsInflight").Child("max"), schema.MaxRequestsInflight.Max, "must be bigger than or equal to 0"))
			}
		}
	}
	if schema.GlobalMaxRequestsInflight != nil {
		if schema.GlobalMaxRequestsInflight.Max < 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("globalMaxRequestsInflight").Child("max"), schema.MaxRequestsInflight.Max, "must be bigger than or equal to 0"))
		}
		if schema.MaxRequestsInflight == nil {
			allErrs = append(allErrs, field.Required(fldPath.Child("maxRequestsInflight"), "required if globalMaxRequestsInflight is specified"))
		} else if schema.GlobalMaxRequestsInflight.Max < schema.MaxRequestsInflight.Max {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("globalMaxRequestsInflight").Child("max"), schema.MaxRequestsInflight.Max, "must be bigger than or equal to maxRequestsInflight.max"))
		}
	}

	if schema.TokenBucket != nil {
		if numConfig > 0 {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("tokenBucket"), "may not specify more than 1 flow control configuration"))
		} else {
			numConfig++
			allErrs = append(allErrs, validateTokenBucketFlowControlSchema(schema.TokenBucket, fldPath.Child("tokenBucket"))...)
		}
	}
	if schema.GlobalTokenBucket != nil {
		if schema.GlobalTokenBucket.QPS == 0 {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("globalTokenBucket").Child("qps"), schema.GlobalTokenBucket.QPS, "must bigger than 0"))
		}
		if schema.TokenBucket == nil {
			allErrs = append(allErrs, field.Required(fldPath.Child("tokenBucket"), "required if globalTokenBucket is specified"))
		} else if schema.GlobalTokenBucket.QPS < schema.TokenBucket.QPS {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("globalTokenBucket").Child("qps"), schema.GlobalTokenBucket.QPS, "must be bigger than or equal to tokenBucket.qps"))
		} else if schema.GlobalTokenBucket.Burst < schema.TokenBucket.Burst {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("globalTokenBucket").Child("burst"), schema.GlobalTokenBucket.Burst, "must be bigger than or equal to tokenBucket.burst"))
		}
	}

	if numConfig == 0 {
		allErrs = append(allErrs, field.Required(fldPath, "must specify a flow control type configuration"))
	}
	return allErrs
}

func validateTokenBucketFlowControlSchema(tokenBucket *proxyv1alpha1.TokenBucketFlowControlSchema, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if tokenBucket.QPS == 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("qps"), tokenBucket.QPS, "must bigger than 0"))
	}

	if tokenBucket.Burst < tokenBucket.QPS {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("burst"), tokenBucket.Burst, "must bigger than qps"))
	}
	return allErrs
}

func ValidateAdaptiveWeightConfig(config *proxyv1alpha1.AdaptiveWeightConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if !config.Enabled {
		return allErrs
	}

	if config.WindowSize < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("windowSize"), config.WindowSize, "must be greater than or equal to 0"))
	}
	if config.WindowSize > 0 && config.WindowSize < 10 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("windowSize"), config.WindowSize, "must be at least 10 for meaningful P99 calculation"))
	}
	if config.MinWeight < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("minWeight"), config.MinWeight, "must be greater than or equal to 0"))
	}
	if config.MaxWeight < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("maxWeight"), config.MaxWeight, "must be greater than or equal to 0"))
	}
	if config.MinWeight > 0 && config.MaxWeight > 0 && config.MinWeight > config.MaxWeight {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("minWeight"), config.MinWeight, "must be less than or equal to maxWeight"))
	}
	if config.AdjustIntervalSeconds < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("adjustIntervalSeconds"), config.AdjustIntervalSeconds, "must be greater than or equal to 0"))
	}
	if config.FailureThreshold < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("failureThreshold"), config.FailureThreshold, "must be greater than or equal to 0"))
	}
	if config.BaseBackoffSeconds < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("baseBackoffSeconds"), config.BaseBackoffSeconds, "must be greater than or equal to 0"))
	}
	if config.MaxBackoffSeconds < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("maxBackoffSeconds"), config.MaxBackoffSeconds, "must be greater than or equal to 0"))
	}
	if config.BaseBackoffSeconds > 0 && config.MaxBackoffSeconds > 0 && config.BaseBackoffSeconds > config.MaxBackoffSeconds {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("baseBackoffSeconds"), config.BaseBackoffSeconds, "must be less than or equal to maxBackoffSeconds"))
	}
	return allErrs
}

func ValidatePriorityQueueConfig(config *proxyv1alpha1.PriorityQueueConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if !config.Enabled {
		return allErrs
	}

	if config.MaxQueueSize < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("maxQueueSize"), config.MaxQueueSize, "must be greater than or equal to 0"))
	}
	if config.MaxWaitSeconds < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("maxWaitSeconds"), config.MaxWaitSeconds, "must be greater than or equal to 0"))
	}
	if config.DefaultPriority < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("defaultPriority"), config.DefaultPriority, "must be greater than or equal to 0"))
	}
	if config.DegradedPriorityThreshold < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("degradedPriorityThreshold"), config.DegradedPriorityThreshold, "must be greater than or equal to 0"))
	}

	verbs := sets.NewString("get", "list", "create", "update", "delete", "deletecollection", "patch", "watch", "proxy", "*")
	for i, rule := range config.PriorityRules {
		rulePath := fldPath.Child("priorityRules").Index(i)
		if rule.Priority < 0 {
			allErrs = append(allErrs, field.Invalid(rulePath.Child("priority"), rule.Priority, "must be greater than or equal to 0"))
		}
		for j, verb := range rule.Verbs {
			if !verbs.Has(strings.ToLower(verb)) {
				allErrs = append(allErrs, field.Invalid(rulePath.Child("verbs").Index(j), verb, "must be a valid verb or '*'"))
			}
		}
	}
	return allErrs
}

func ValidateClusterGroupConfig(config *proxyv1alpha1.ClusterGroupConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if !config.Enabled {
		return allErrs
	}

	if len(config.GroupName) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("groupName"), "groupName is required when clusterGroup is enabled"))
	}
	if len(config.VirtualEndpoint) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("virtualEndpoint"), "virtualEndpoint is required when clusterGroup is enabled"))
	}
	if len(config.LabelSelector) > 0 {
		if _, err := labels.Parse(config.LabelSelector); err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("labelSelector"), config.LabelSelector, "invalid label selector: "+err.Error()))
		}
	}
	backupSet := sets.NewString()
	for i, backup := range config.BackupClusters {
		if backupSet.Has(backup) {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("backupClusters").Index(i), backup))
		}
		backupSet.Insert(backup)
		if len(config.PrimaryCluster) > 0 && backup == config.PrimaryCluster {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("backupClusters").Index(i), backup, "backup cluster must not be the same as primaryCluster"))
		}
	}
	return allErrs
}
