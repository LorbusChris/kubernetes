/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:conversion-gen:explicit-from=net/url.Values
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeLogOptions is the query options for a Pod's logs REST call
type NodeLogOptions struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	Selector string `json:"selector,omitempty"`

	// +optional
	Role string `json:"role,omitempty"`

	// the log path to fetch
	// +optional
	Path string `json:"path,omitempty"`

	// --path=journal specific arguments

	// +optional
	Grep string `json:"grep,omitempty"`

	// +optional
	GrepCaseSensitive bool `json:"grepCaseSensitive,omitempty"`

	// +optional
	Boot int `json:"boot,omitempty"`

	// +optional
	BootChanged bool `json:"bootChanged,omitempty"`

	// +optional
	Services NodeServiceList `json:"services,omitempty"`

	// Follow the log stream of the node. Defaults to false.
	// +optional
	Follow bool `json:"follow,omitempty" protobuf:"varint,2,opt,name=follow"`

	// A relative time in seconds before the current time from which to show logs.
	// Only one of sinceSeconds or sinceTime may be specified.
	// +optional
	SinceSeconds *int64 `json:"sinceSeconds,omitempty" protobuf:"varint,4,opt,name=sinceSeconds"`

	// An RFC3339 timestamp from which to show logs.
	// If this value is in the future, no logs will be returned.
	// +optional
	SinceTime *metav1.Time `json:"sinceTime,omitempty" protobuf:"bytes,5,opt,name=sinceTime"`

	// An RFC3339 timestamp until which to show logs.
	// If this value is in the future, no logs will be returned.
	// +optional
	UntilTime *metav1.Time `json:"untilTime,omitempty" protobuf:"bytes,5,opt,name=untilTime"`

	// +optional
	Tail int `json:"tail,omitempty"`

	// If set, the number of lines from the end of the logs to show. If not specified,
	// logs are shown from the creation of the node or sinceSeconds or sinceTime
	// +optional
	TailLines *int64 `json:"tailLines,omitempty" protobuf:"varint,7,opt,name=tailLines"`

	// +optional
	Output string `json:"output,omitempty"`

	// If set, the number of bytes to read from the server before terminating the
	// log output. This may not display a complete final line of logging, and may return
	// slightly more or slightly less than the specified limit.
	// +optional
	LimitBytes *int64 `json:"limitBytes,omitempty" protobuf:"varint,8,opt,name=limitBytes"`

	// insecureSkipTLSVerifyBackend indicates that the apiserver should not confirm the validity of the
	// serving certificate of the backend it is connecting to.  This will make the HTTPS connection between the apiserver
	// and the backend insecure. This means the apiserver cannot verify the log data it is receiving came from the real
	// kubelet.  If the kubelet is configured to verify the apiserver's TLS credentials, it does not mean the
	// connection to the real kubelet is vulnerable to a man in the middle attack (e.g. an attacker could not intercept
	// the actual log data coming from the real kubelet).
	// +optional
	InsecureSkipTLSVerifyBackend bool `json:"insecureSkipTLSVerifyBackend,omitempty" protobuf:"varint,9,opt,name=insecureSkipTLSVerifyBackend"`
}

// NodeService is a service running on the node
type NodeService string

// NodeServiceList is a list of services running on the node
type NodeServiceList []NodeService
