// +build linux

/*
Copyright 2020 The Kubernetes Authors.

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

package kubelet

import (
	"fmt"
)

// getLoggingCmd returns the journalctl cmd and arguments for the given journalArgs and boot
func getLoggingCmd(a *journalArgs, boot int) (string, []string) {
	args := []string{
		"--utc",
		"--no-pager",
	}
	if len(a.Since) > 0 {
		args = append(args, "--since="+a.Since)
	}
	if len(a.Until) > 0 {
		args = append(args, "--until="+a.Until)
	}
	if a.Tail > 0 {
		args = append(args, "--pager-end", fmt.Sprintf("--lines=%d", a.Tail))
	}
	if len(a.Format) > 0 {
		args = append(args, "--output="+a.Format)
	}
	for _, unit := range a.Units {
		if len(unit) > 0 {
			args = append(args, "--unit="+unit)
		}
	}
	if len(a.Pattern) > 0 {
		args = append(args, "--grep="+a.Pattern)
		args = append(args, fmt.Sprintf("--case-sensitive=%t", a.CaseSensitive))
	}

	args = append(args, "--boot", fmt.Sprintf("%d", boot))

	return "journalctl", args
}
