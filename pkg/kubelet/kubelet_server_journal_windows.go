// +build windows

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
	"strings"
)

// getLoggingCmd returns the powershell cmd and arguments for the given journalArgs and boot
func getLoggingCmd(a *journalArgs, boot int) (string, []string) {
	// The WinEvent log does not support querying by boot
	// Set the cmd to return true on windows in case boot is not 0
	if boot != 0 {
		return "cd.", []string{}
	}

	args := []string{
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command",
	}

	psCmd := "Get-WinEvent -FilterHashtable @{LogName='Application'"
	if len(a.Since) > 0 {
		psCmd += fmt.Sprintf("; StartTime='%s'", a.Since)
	}
	if len(a.Until) > 0 {
		psCmd += fmt.Sprintf("; EndTime='%s'", a.Until)
	}
	var units []string
	for _, unit := range a.Units {
		if len(unit) > 0 {
			units = append(units, "'"+unit+"'")
		}
	}
	if len(units) > 0 {
		psCmd += fmt.Sprintf("; ProviderName=%s", strings.Join(units, ","))
	}
	psCmd += "}"
	if a.Tail > 0 {
		psCmd += fmt.Sprintf(" -MaxEvents %d", a.Tail)
	}
	psCmd += " | Sort-Object TimeCreated"
	if len(a.Pattern) > 0 {
		psCmd += fmt.Sprintf(" | Where-Object -Property Message -Match %s", a.Pattern)
	}
	psCmd += " | Format-Table -AutoSize -Wrap"

	args = append(args, psCmd)

	return "PowerShell.exe", args
}
