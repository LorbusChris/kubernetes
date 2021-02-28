/*
Copyright 2014 The Kubernetes Authors.

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

package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"
	corev1alpha1 "k8s.io/api/core/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	kerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/polymorphichelpers"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

const (
	logsUsageStr = "logs [-f] [-p] (POD | TYPE/NAME) [-c CONTAINER]"
)

var (
	logsLong = templates.LongDesc(i18n.T(`
		Print the logs for a container in a pod or specified resource. 
		If the pod has only one container, the container name is optional.`))

	logsExample = templates.Examples(i18n.T(`
		# Return snapshot logs from pod nginx with only one container
		kubectl logs nginx

		# Return snapshot logs from pod nginx with multi containers
		kubectl logs nginx --all-containers=true

		# Return snapshot logs from all containers in pods defined by label app=nginx
		kubectl logs -lapp=nginx --all-containers=true

		# Return snapshot of previous terminated ruby container logs from pod web-1
		kubectl logs -p -c ruby web-1

		# Begin streaming the logs of the ruby container in pod web-1
		kubectl logs -f -c ruby web-1

		# Begin streaming the logs from all containers in pods defined by label app=nginx
		kubectl logs -f -lapp=nginx --all-containers=true

		# Display only the most recent 20 lines of output in pod nginx
		kubectl logs --tail=20 nginx

		# Show all logs from pod nginx written in the last hour
		kubectl logs --since=1h nginx

		# Show logs from a kubelet with an expired serving certificate
		kubectl logs --insecure-skip-tls-verify-backend nginx

		# Return snapshot logs from first container of a job named hello
		kubectl logs job/hello

		# Return snapshot logs from container nginx-1 of a deployment named nginx
		kubectl logs deployment/nginx -c nginx-1

		// TODO(lorbus) move to nodes subcommand
		# See what logs are available in masters in /var/log/
		kubectl logs nodes --role master --path=/
		
		# Display cron log file (/var/log/cron) from all masters
		kubectl logs nodes --role master --path=cron
		
		# Show kubelet and crio journal logs from all masters
		kubectl logs nodes --role master --path journal -s kubelet -s crio
		
		# Show kubelet log file (/var/log/kubelet/kubelet.log) from all Windows worker nodes
		kubectl logs nodes --label kubernetes.io/os=windows --path kubelet/kubelet.log
		
		# Display docker service log entries from a specific node
		kubectl logs nodes <node-name> --service docker`))

	selectorTail    int64 = 10
	logsUsageErrStr       = fmt.Sprintf("expected '%s'.\nPOD or TYPE/NAME is a required argument for the logs command", logsUsageStr)
)

const (
	defaultPodLogsTimeout = 20 * time.Second
)

// LogsOptions holds all the options for running kubectl logs
type LogsOptions struct {
	Object      runtime.Object
	Options     runtime.Object
	Resources   []string
	ResourceArg string

	// common log options for all supported object types
	Selector                     string
	LimitBytes                   int64
	Tail                         int64
	TailSpecified                bool
	Timestamps                   bool
	SinceTime                    string
	SinceSeconds                 time.Duration
	UntilTime                    string
	UntilSeconds                 time.Duration
	Prefix                       bool
	InsecureSkipTLSVerifyBackend bool

	// PodLogOptions
	Namespace            string
	AllContainers        bool
	MaxFollowConcurrency int
	IgnoreLogErrors      bool
	Container            string
	Follow               bool
	Previous             bool
	GetPodTimeout        time.Duration
	// PodLogOptions in case a container name was given via --container
	ContainerNameSpecified         bool
	containerNameFromRefSpecRegexp *regexp.Regexp

	// NodeLogOptions
	NodeLogsPath string
	NodeRole     string
	// NodeLogOptions in case --path=journal is specified
	NodeServices      []string
	Boot              int
	BootChanged       bool
	Grep              string
	GrepCaseSensitive bool
	Output            string
	// NodeLogOptions --output format arguments
	Raw   bool
	Unify bool

	RESTClientGetter genericclioptions.RESTClientGetter
	LogsForObject    polymorphichelpers.LogsForObjectFunc

	genericclioptions.IOStreams
}

// NewLogsOptions constructs a new LogsOptions object
func NewLogsOptions(streams genericclioptions.IOStreams, allContainers, grepCaseSensitive bool, nodeLogsPath string) *LogsOptions {
	return &LogsOptions{
		IOStreams:            streams,
		AllContainers:        allContainers,
		Tail:                 -1,
		MaxFollowConcurrency: 5,

		containerNameFromRefSpecRegexp: regexp.MustCompile(`spec\.(?:initContainers|containers|ephemeralContainers){(.+)}`),

		NodeLogsPath:      nodeLogsPath,
		GrepCaseSensitive: grepCaseSensitive,
	}
}

// NewCmdLogs creates a new pod logs command
func NewCmdLogs(f cmdutil.Factory, streams genericclioptions.IOStreams) *cobra.Command {
	o := NewLogsOptions(streams, false, true, "journal")

	cmd := &cobra.Command{
		Use:                   logsUsageStr,
		DisableFlagsInUseLine: true,
		Short:                 i18n.T("Print the logs for a container in a pod"),
		Long:                  logsLong,
		Example:               logsExample,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Validate())
			cmdutil.CheckErr(o.RunLogs())
		},
	}
	o.AddFlags(cmd)
	return cmd
}

// AddFlags adds flags to the kubectl logs command
func (o *LogsOptions) AddFlags(cmd *cobra.Command) {
	// common flags for all supported object types
	cmd.Flags().StringVarP(&o.Selector, "selector", "l", o.Selector, "Selector (label query) to filter on.")
	cmd.Flags().Int64Var(&o.LimitBytes, "limit-bytes", o.LimitBytes, "Maximum bytes of logs to return. Defaults to no limit.")
	cmd.Flags().Int64Var(&o.Tail, "tail", o.Tail, "Lines of recent log file to display (not more than 100k). Defaults to -1 with no selector, showing all log lines otherwise 10, if a selector is provided.")
	cmd.Flags().BoolVar(&o.Prefix, "prefix", o.Prefix, "Prefix each log line with the log source (pod name and container name or node name)")
	cmd.Flags().BoolVar(&o.Timestamps, "timestamps", o.Timestamps, "Include timestamps on each line in the log output")
	cmd.Flags().StringVar(&o.SinceTime, "since-time", o.SinceTime, i18n.T("Only return logs after a specific date (RFC3339). Defaults to all logs. Only one of since-time / since may be used."))
	cmd.Flags().DurationVar(&o.SinceSeconds, "since", o.SinceSeconds, "Only return logs newer than a relative duration like 5s, 2m, or 3h. Defaults to all logs. Only one of since-time / since may be used.")
	cmd.Flags().StringVar(&o.UntilTime, "until-time", o.UntilTime, "Only return logs before a specific date (RFC3339).Defaults to all logs. Only one of until-time / until may be used.")
	cmd.Flags().DurationVar(&o.UntilSeconds, "until", o.UntilSeconds, "Only return logs older than a relative duration like 5s, 2m, or 3h. Defaults to all logs. Only one of until-time / until may be used.")
	cmd.Flags().BoolVar(&o.InsecureSkipTLSVerifyBackend, "insecure-skip-tls-verify-backend", o.InsecureSkipTLSVerifyBackend,
		"Skip verifying the identity of the kubelet that logs are requested from.  In theory, an attacker could provide invalid log content back. You might want to use this if your kubelet serving certificates have expired.")

	// flags specific to pod logs
	cmd.Flags().BoolVar(&o.AllContainers, "all-containers", o.AllContainers, "Get all containers' logs in the pod(s).")
	cmd.Flags().IntVar(&o.MaxFollowConcurrency, "max-log-requests", o.MaxFollowConcurrency, "Specify maximum number of concurrent logs to follow when using by a selector. Defaults to 5.")
	cmd.Flags().BoolVar(&o.IgnoreLogErrors, "ignore-errors", o.IgnoreLogErrors, "If watching / following pod logs, allow for any errors that occur to be non-fatal")
	cmd.Flags().StringVarP(&o.Container, "container", "c", o.Container, "Print the logs of this container")
	cmd.Flags().BoolVarP(&o.Follow, "follow", "f", o.Follow, "Specify if the logs should be streamed.")
	cmd.Flags().BoolVarP(&o.Previous, "previous", "p", o.Previous, "If true, print the logs for the previous instance of the container in a pod if it exists.")
	cmdutil.AddPodRunningTimeoutFlag(cmd, defaultPodLogsTimeout)

	// flags specific to node logs
	cmd.Flags().StringVar(&o.NodeRole, "role", o.NodeRole, "Set a label selector by node role.")
	cmd.Flags().StringVar(&o.NodeLogsPath, "path", o.NodeLogsPath, "Retrieve the specified path within the node's /var/logs/ folder. The 'journal' value will allow querying the journal on supported operating systems.")
	cmd.Flags().StringSliceVarP(&o.NodeServices, "service", "s", o.NodeServices, "Return log entries from the specified node service(s). Only applies to node journal unit logs and windows event provider logs.")
	cmd.Flags().IntVar(&o.Boot, "boot", o.Boot, " Show messages from a specific boot. Use negative numbers, allowed [-100, 0], passing invalid boot offset will fail retrieving logs. Only applies to node journal logs.")
	cmd.Flags().StringVarP(&o.Grep, "grep", "g", o.Grep, "Filter log entries by the provided regex pattern. Only applies to node journal logs.")
	cmd.Flags().BoolVar(&o.GrepCaseSensitive, "case-sensitive", o.GrepCaseSensitive, "Filters are case sensitive by default. Pass --case-sensitive=false to do a case insensitive filter.")
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "Display journal logs in an alternate format (short, cat, json, short-unix). Only applies to node journal logs.")
	cmd.Flags().BoolVar(&o.Raw, "raw", o.Raw, "Perform no transformation of the returned data.")
	cmd.Flags().BoolVar(&o.Unify, "unify", o.Unify, "Interleave logs by sorting the output. Defaults on when viewing node journal logs.")
}

// ToPodLogOptions assembles the PodLogOptions object
func (o *LogsOptions) ToPodLogOptions() (*corev1.PodLogOptions, error) {
	logOptions := &corev1.PodLogOptions{
		Container:                    o.Container,
		Follow:                       o.Follow,
		Previous:                     o.Previous,
		Timestamps:                   o.Timestamps,
		InsecureSkipTLSVerifyBackend: o.InsecureSkipTLSVerifyBackend,
	}

	if len(o.SinceTime) > 0 {
		t, err := util.ParseRFC3339(o.SinceTime, metav1.Now)
		if err != nil {
			return nil, err
		}

		logOptions.SinceTime = &t
	}

	if o.LimitBytes != 0 {
		logOptions.LimitBytes = &o.LimitBytes
	}

	if o.SinceSeconds != 0 {
		// round up to the nearest second
		sec := int64(o.SinceSeconds.Round(time.Second).Seconds())
		logOptions.SinceSeconds = &sec
	}

	if len(o.Selector) > 0 && o.Tail == -1 && !o.TailSpecified {
		logOptions.TailLines = &selectorTail
	} else if o.Tail != -1 {
		logOptions.TailLines = &o.Tail
	}

	return logOptions, nil
}

// ToNodeLogOptions assembles the PodLogOptions object
func (o *LogsOptions) ToNodeLogOptions() (*corev1alpha1.NodeLogOptions, error) {
	logOptions := &corev1alpha1.NodeLogOptions{
		Role:                         o.NodeRole,
		Path:                         o.NodeLogsPath,
		GrepCaseSensitive:            o.GrepCaseSensitive,
		Grep:                         o.Grep,
		InsecureSkipTLSVerifyBackend: o.InsecureSkipTLSVerifyBackend,
	}

	if len(o.SinceTime) > 0 {
		t, err := util.ParseRFC3339(o.SinceTime, metav1.Now)
		if err != nil {
			return nil, err
		}

		logOptions.SinceTime = &t
	}

	if o.LimitBytes != 0 {
		logOptions.LimitBytes = &o.LimitBytes
	}

	if o.SinceSeconds != 0 {
		// round up to the nearest second
		sec := int64(o.SinceSeconds.Round(time.Second).Seconds())
		logOptions.SinceSeconds = &sec
	}

	if len(o.Selector) > 0 && o.Tail == -1 && !o.TailSpecified {
		logOptions.TailLines = &selectorTail
	} else if o.Tail != -1 {
		logOptions.TailLines = &o.Tail
	}

	return logOptions, nil
}

// Complete assembles the logs command
func (o *LogsOptions) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	o.TailSpecified = cmd.Flag("tail").Changed

	o.Resources = args

	// ResourceArg defaults to Pod Name

	switch len(args) {
	case 0:
		if len(o.Selector) == 0 {
			return cmdutil.UsageErrorf(cmd, "%s", logsUsageErrStr)
		}
	case 1:
		o.ResourceArg = args[0]
		if len(o.Selector) != 0 {
			return cmdutil.UsageErrorf(cmd, "only a selector (-l) or a POD name is allowed")
		}
	case 2:
		o.ResourceArg = args[0]
		o.Container = args[1]
	default:
		return cmdutil.UsageErrorf(cmd, "%s", logsUsageErrStr)
	}
	var err error

	// TODO(lorbus) support nodes
	if o.Object == nil {
		builder := f.NewBuilder().
			WithScheme(scheme.Scheme, scheme.Scheme.PrioritizedVersionsAllGroups()...).
			NamespaceParam(o.Namespace).DefaultNamespace().
			SingleResourceType()
		if o.ResourceArg != "" {
			builder.ResourceNames("pods", o.ResourceArg)
		}
		if o.Selector != "" {
			builder.ResourceTypes("pods").LabelSelectorParam(o.Selector)
		}
		infos, err := builder.Do().Infos()
		if err != nil {
			return err
		}
		if o.Selector == "" && len(infos) != 1 {
			return errors.New("expected a resource")
		}
		o.Object = infos[0].Object
		if o.Selector != "" && len(o.Object.(*corev1.PodList).Items) == 0 {
			fmt.Fprintf(o.ErrOut, "No resources found in %s namespace.\n", o.Namespace)
		}
	}

	switch o.Object.GetObjectKind().GroupVersionKind().Kind {
	case "Pod":
		o.ContainerNameSpecified = cmd.Flag("container").Changed

		o.Namespace, _, err = f.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			return err
		}

		o.GetPodTimeout, err = cmdutil.GetPodRunningTimeoutFlag(cmd)
		if err != nil {
			return err
		}

		o.Options, err = o.ToPodLogOptions()
		if err != nil {
			return err
		}

	case "Node":
		if !cmd.Flags().Lookup("unify").Changed {
			o.Unify = o.NodeLogsPath == "journal"
		}

		builder := f.NewBuilder().
			WithScheme(scheme.Scheme, scheme.Scheme.PrioritizedVersionsAllGroups()...).
			SingleResourceType()

		if len(o.Resources) > 0 {
			builder.ResourceNames("nodes", o.Resources...)
		}
		if len(o.NodeRole) > 0 {
			req, err := labels.NewRequirement(fmt.Sprintf("node-role.kubernetes.io/%s", o.NodeRole), selection.Exists, nil)
			if err != nil {
				return fmt.Errorf("invalid --role: %v", err)
			}
			o.Selector = req.String()
		}
		if len(o.Selector) > 0 {
			builder.ResourceTypes("nodes").LabelSelectorParam(o.Selector)
		}

		o.BootChanged = cmd.Flag("boot").Changed

		o.Options, err = o.ToNodeLogOptions()
		if err != nil {
			return err
		}
	}

	o.RESTClientGetter = f
	o.LogsForObject = polymorphichelpers.LogsForObjectFn

	return nil
}

// Validate validates the logs command
func (o LogsOptions) Validate() error {
	if len(o.SinceTime) > 0 && o.SinceSeconds != 0 {
		return fmt.Errorf("at most one of `sinceTime` or `sinceSeconds` may be specified")
	}
	if o.LimitBytes < 0 {
		return fmt.Errorf("--limit-bytes must be greater than 0")
	}

	switch logsOptions := o.Options.(type) {
	case *corev1.PodLogOptions:
		if o.AllContainers && len(logsOptions.Container) > 0 {
			return fmt.Errorf("--all-containers=true should not be specified with container name %s", logsOptions.Container)
		}

		if o.ContainerNameSpecified && len(o.Resources) == 2 {
			return fmt.Errorf("only one of -c or an inline [CONTAINER] arg is allowed")
		}
		if logsOptions.SinceSeconds != nil && *logsOptions.SinceSeconds < int64(0) {
			return fmt.Errorf("--since must be greater than 0")
		}
		if logsOptions.TailLines != nil && *logsOptions.TailLines < -1 {
			return fmt.Errorf("--tail must be greater than or equal to -1")
		}
	case *corev1alpha1.NodeLogOptions:
		if len(o.Resources) == 0 && len(o.Selector) == 0 {
			return fmt.Errorf("at least one node name or a selector (-l) must be specified")
		}
		if len(o.Resources) > 0 && len(o.Selector) > 0 {
			return fmt.Errorf("node names and selector may not both be specified")
		}
		if o.BootChanged && (o.Boot < -100 || o.Boot > 0) {
			return fmt.Errorf("--boot accepts values [-100, 0]")
		}
		if logsOptions.SinceSeconds != nil && *logsOptions.SinceSeconds < int64(0) {
			return fmt.Errorf("--since must be greater than 0")
		}
		if logsOptions.TailLines != nil && *logsOptions.TailLines < -1 {
			return fmt.Errorf("--tail must be greater than or equal to -1")
		}
	default:
		return errors.New("unexpected logs options object")
	}

	return nil
}

// RunLogs retrieves logs for the object referred to in LogsOptions
func (o LogsOptions) RunLogs() error {
	requests, err := o.LogsForObject(o.RESTClientGetter, o.Object, o.Options, o.GetPodTimeout, o.AllContainers)
	if err != nil {
		return err
	}

	// buffer output for slightly better streaming performance
	out := bufio.NewWriterSize(o.Out, 1024*16)
	defer out.Flush()

	if o.Follow && len(requests) > 1 {
		if len(requests) > o.MaxFollowConcurrency {
			return fmt.Errorf(
				"you are attempting to follow %d log streams, but maximum allowed concurrency is %d, use --max-log-requests to increase the limit",
				len(requests), o.MaxFollowConcurrency,
			)
		}

		return o.parallelConsumeRequest(requests)
	}

	var errs []error
	if o.Unify {
		// unified output is each source, interleaved in lexographic order (assumes
		// the source input is sorted by time)
		var readers []prefixingReader
		for objRef, request := range requests {
			reader, writer := io.Pipe()
			wg := &sync.WaitGroup{}
			wg.Add(len(requests))
			readers = append(readers, prefixingReader{
				R: reader,
			})
			go func() {
				defer wg.Done()
				err := o.ConsumeRequest(writer, request, objRef)
				writer.CloseWithError(err)
			}()
		}
		_, err := NewMergeReader(readers...).WriteTo(out)
		if agg := kerrs.Flatten(kerrs.NewAggregate([]error{err})); agg != nil {
			errs = append(errs, agg.Errors()...)
		}

		if len(errs) > 0 {
			for _, err := range errs {
				fmt.Fprintf(o.ErrOut, "error: %v\n", err)
				if err, ok := err.(*apierrors.StatusError); ok && err.ErrStatus.Details != nil {
					for _, cause := range err.ErrStatus.Details.Causes {
						fmt.Fprintf(o.ErrOut, "  %s\n", cause.Message)
					}
				}
			}
			return cmdutil.ErrExit
		}
	}

	return o.sequentialConsumeRequest(requests)
}

func (o LogsOptions) parallelConsumeRequest(requests map[corev1.ObjectReference]rest.ResponseWrapper) error {
	reader, writer := io.Pipe()
	wg := &sync.WaitGroup{}
	wg.Add(len(requests))
	for objRef, request := range requests {
		go func(objRef corev1.ObjectReference, request rest.ResponseWrapper) {
			defer wg.Done()
			if err := o.ConsumeRequest(o.Out, request, objRef); err != nil {
				if !o.IgnoreLogErrors {
					writer.CloseWithError(err)

					// It's important to return here to propagate the error via the pipe
					return
				}

				fmt.Fprintf(writer, "error: %v\n", err)
			}

		}(objRef, request)
	}

	go func() {
		wg.Wait()
		writer.Close()
	}()

	_, err := io.Copy(o.Out, reader)
	return err
}

func (o LogsOptions) sequentialConsumeRequest(requests map[corev1.ObjectReference]rest.ResponseWrapper) error {
	for objRef, request := range requests {
		if err := o.ConsumeRequest(o.Out, request, objRef); err != nil {
			if !o.IgnoreLogErrors {
				return err
			}

			fmt.Fprintf(o.Out, "error: %v\n", err)
		}
	}

	return nil
}

func optionallyDecompress(out io.Writer, in io.Reader) error {
	bufferSize := 4096
	buf := bufio.NewReaderSize(in, bufferSize)
	head, err := buf.Peek(1024)
	if err != nil && err != io.EOF {
		return err
	}
	if _, err := gzip.NewReader(bytes.NewBuffer(head)); err != nil {
		// not a gzipped stream
		_, err = io.Copy(out, buf)
		return err
	}
	r, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, r)
	return err
}

func outputDirectoryEntriesOrContent(out io.Writer, in io.Reader, prefix []byte) error {
	bufferSize := 4096
	buf := bufio.NewReaderSize(in, bufferSize)

	// turn href links into lines of output
	content, _ := buf.Peek(bufferSize)
	if bytes.HasPrefix(content, []byte("<pre>")) {
		reLink := regexp.MustCompile(`href="([^"]+)"`)
		s := bufio.NewScanner(buf)
		s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			matches := reLink.FindSubmatchIndex(data)
			if matches == nil {
				advance = bytes.LastIndex(data, []byte("\n"))
				if advance == -1 {
					advance = 0
				}
				return advance, nil, nil
			}
			advance = matches[1]
			token = data[matches[2]:matches[3]]
			return advance, token, nil
		})
		for s.Scan() {
			if _, err := out.Write(prefix); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, s.Text()); err != nil {
				return err
			}
		}
		return s.Err()
	}

	// without a prefix we can copy directly
	if len(prefix) == 0 {
		_, err := io.Copy(out, buf)
		return err
	}

	r := NewMergeReader(prefixingReader{R: buf, Prefix: prefix})
	_, err := r.WriteTo(out)
	return err
}

// ConsumeRequest reads the data from request and writes into
// the out writer. It buffers data from requests until the newline or io.EOF
// occurs in the data, so it doesn't interleave logs sub-line
// when running concurrently.
//
// A successful read returns err == nil, not err == io.EOF.
// Because the function is defined to read from request until io.EOF, it does
// not treat an io.EOF as an error to be reported.
func (o LogsOptions) ConsumeRequest(out io.Writer, request rest.ResponseWrapper, ref corev1.ObjectReference) error {
	readCloser, err := request.Stream(context.TODO())
	if err != nil {
		return err
	}
	defer readCloser.Close()

	// raw output implies we may be getting binary content directly
	// from the remote and so we want to perform no translation
	if o.Raw {
		// TODO: optionallyDecompress should be implemented by checking
		// the content-encoding of the response, but we perform optional
		// decompression here in case the content of the logs on the server
		// is also gzipped.
		return optionallyDecompress(out, readCloser)
	}

	prefix := ""
	switch ref.Kind {
	case "Pod":
		if o.Prefix && ref.FieldPath != "" && ref.Name != "" {
			// We rely on ref.FieldPath to contain a reference to a container
			// including a container name (not an index) so we can get a container name
			// without making an extra API request.
			var containerName string
			containerNameMatches := o.containerNameFromRefSpecRegexp.FindStringSubmatch(ref.FieldPath)
			if len(containerNameMatches) == 2 {
				containerName = containerNameMatches[1]
			}

			prefix = fmt.Sprintf("[pod/%s/%s] ", ref.Name, containerName)
		}
	case "Node":
		if o.Prefix && ref.Name != "" {
			prefix = fmt.Sprintf("[node/%s] ", ref.Name)
		}
	}

	if o.Unify {
		prefix = ""
	}

	return outputDirectoryEntriesOrContent(out, readCloser, []byte(prefix))
}

// Reader wraps an io.Reader and inserts the provided prefix at the
// beginning of the output and before each newline character found
// in the stream.
type prefixingReader struct {
	R      io.Reader
	Prefix []byte
}

type mergeReader []prefixingReader

// NewMergeReader attempts to display the provided readers as line
// oriented output in lexographic order by always reading the next
// available line from the reader with the "smallest" line.
//
// For example, given the readers with the following lines:
//   1: A
//      B
//      D
//   2: C
//      D
//      E
//
//  the reader would contain:
//      A
//      B
//      C
//      D
//      D
//      E
//
// The merge reader uses bufio.NewReader() for each input and the
// ReadLine() method to find the next shortest input. If a given
// line is longer than the buffer size of 4096, and all readers
// have the same initial 4096 characters, the order is undefined.
func NewMergeReader(r ...prefixingReader) io.WriterTo {
	return mergeReader(r)
}

// WriteTo copies the provided readers into the provided output.
func (r mergeReader) WriteTo(out io.Writer) (int64, error) {
	// shortcut common cases
	switch len(r) {
	case 0:
		return 0, nil
	case 1:
		if len(r[0].Prefix) == 0 {
			return io.Copy(out, r[0].R)
		}
	}

	// initialize the buffered readers
	bufSize := 4096
	var buffers sortedBuffers
	var errs []error
	for _, in := range r {
		buf := &buffer{
			r:      bufio.NewReaderSize(in.R, bufSize),
			prefix: in.Prefix,
		}
		if err := buf.next(); err != nil {
			errs = append(errs, err)
			continue
		}
		buffers = append(buffers, buf)
	}

	var n int64
	for len(buffers) > 0 {
		// find the lowest buffer
		sort.Sort(buffers)

		// write out the line from the smallest buffer
		buf := buffers[0]

		if len(buf.prefix) > 0 {
			b, err := out.Write(buf.prefix)
			n += int64(b)
			if err != nil {
				return n, err
			}
		}

		for {
			done := !buf.linePrefix
			b, err := out.Write(buf.line)
			n += int64(b)
			if err != nil {
				return n, err
			}

			// try to fill the buffer, and if we get an error reading drop this source
			if err := buf.next(); err != nil {
				errs = append(errs, err)
				buffers = buffers[1:]
				break
			}

			// we reached the end of our line
			if done {
				break
			}
		}
		b, err := fmt.Fprintln(out)
		n += int64(b)
		if err != nil {
			return n, err
		}
	}

	return n, kerrs.FilterOut(kerrs.NewAggregate(errs), func(err error) bool { return err == io.EOF })
}

type buffer struct {
	r          *bufio.Reader
	prefix     []byte
	line       []byte
	linePrefix bool
}

func (b *buffer) next() error {
	var err error
	b.line, b.linePrefix, err = b.r.ReadLine()
	return err
}

type sortedBuffers []*buffer

func (buffers sortedBuffers) Less(i, j int) bool {
	return bytes.Compare(buffers[i].line, buffers[j].line) < 0
}
func (buffers sortedBuffers) Swap(i, j int) {
	buffers[i], buffers[j] = buffers[j], buffers[i]
}
func (buffers sortedBuffers) Len() int {
	return len(buffers)
}
