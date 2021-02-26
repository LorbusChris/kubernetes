/*
Copyright 2016 The Kubernetes Authors.

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

package v1

import (
	"context"

	v1 "k8s.io/api/core/v1"
	v1alpha1 "k8s.io/api/core/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	scheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
)

// The NodeExpansion interface allows manually adding extra methods to the NodeInterface.
type NodeExpansion interface {
	// PatchStatus modifies the status of an existing node. It returns the copy
	// of the node that the server returns, or an error.
	PatchStatus(ctx context.Context, nodeName string, data []byte) (*v1.Node, error)
	GetLogs(nodeName string, opts *v1alpha1.NodeLogOptions) *restclient.Request
}

// Get constructs a request for getting the logs for a node
func (c *nodes) GetLogs(nodeName string, opts *v1alpha.NodeLogOptions) *restclient.Request {
	req := c.client.Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy", "logs").
		VersionedParams(opts, scheme.ParameterCodec).
		Suffix(opts.NodeLogsPath).
		SetHeader("Accept", "text/plain, */*").
		SetHeader("Accept-Encoding", "gzip")

	if opts.NodeLogsPath == "journal" {
		if len(opts.UntilTime) > 0 {
			request.Param("until", o.UntilTime)
		}
		if len(opts.SinceTime) > 0 {
			req.Param("since", o.SinceTime)
		}
		if len(opts.Output) > 0 {
			req.Param("output", o.Output)
		}
		if opts.BootChanged {
			req.Param("boot", fmt.Sprintf("%d", o.Boot))
		}
		if len(opts.NodeServices) > 0 {
			for _, service := range opts.NodeServices {
				req.Param("node-service", service)
			}
		}
		if len(opts.Grep) > 0 {
			req.Param("grep", opts.Grep)
			req.Param("case-sensitive", fmt.Sprintf("%t", opts.GrepCaseSensitive))
		}
		if opts.Tail > 0 {
			req.Param("tail", strconv.FormatInt(opts.Tail, 10))
		}
	}

	return req
}

// PatchStatus modifies the status of an existing node. It returns the copy of
// the node that the server returns, or an error.
func (c *nodes) PatchStatus(ctx context.Context, nodeName string, data []byte) (*v1.Node, error) {
	result := &v1.Node{}
	err := c.client.Patch(types.StrategicMergePatchType).
		Resource("nodes").
		Name(nodeName).
		SubResource("status").
		Body(data).
		Do(ctx).
		Into(result)
	return result, err
}
