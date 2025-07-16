\# mompfdie.coretools



Utility module for scheduled task logic, logging, and Windows EventLog management. Designed for reusable PowerShell functions in automation projects and recurring administrative scripts.



\## 📦 Functions Overview



| Function | Description |

|----------|-------------|

| `Test-TaskDue` | Checks if a task is due based on registry config |

| `Update-TaskStatus` | Updates registry with success/error state |

| `Write-TaskLog` | Appends structured log entries to a task-specific log file |

| `Get-TaskConfig` | Reads task registry configuration as an object |

| `Start-TaskTranscriptIfVerbose` | Starts transcript logging if LogLevel is 'Verbose' |

| `Stop-TranscriptIfRunning` | Stops an active transcript if running |

| `New-MompfdieEventLog` | Creates a new Windows EventLog + source (admin required) |

| `New-MompfdieEventLogSource` | Adds a new source to an existing EventLog (admin required) |

| `Write-MompfdieEventLog` | Writes entries into the Windows EventLog |



\## 🧱 Structure \& Requirements



\- Registry entries under: `HKCU:\\Software\\MompfdieTasks\\Tasks\\<TaskName>`

\- Logs are stored per task, typically in `$PSScriptRoot\\CleanupScript.log`

\- Requires PowerShell 5.1 or newer

\- Optionally signed (for `AllSigned` policy environments)



\## 🧪 Example

```powershell

Import-Module mompfdie.coretools



if (Test-TaskDue -TaskName 'CleanupTask') {

&nbsp;   Start-TaskTranscriptIfVerbose -TaskName 'CleanupTask'



&nbsp;   try {

&nbsp;       # ... perform the task ...

&nbsp;       Update-TaskStatus -TaskName 'CleanupTask'

&nbsp;   }

&nbsp;   catch {

&nbsp;       Update-TaskStatus -TaskName 'CleanupTask' -ErrorMessage $\_.Exception.Message

&nbsp;   }



&nbsp;   Stop-TranscriptIfRunning

}

```



\## 🛠 Initial Registry Setup

```powershell

New-Item -Path 'HKCU:\\Software\\MompfdieTasks\\Tasks\\CleanupTask' -Force | Out-Null

Set-ItemProperty -Path 'HKCU:\\Software\\MompfdieTasks\\Tasks\\CleanupTask' -Name 'IntervalMinutes' -Value 240

Set-ItemProperty -Path 'HKCU:\\Software\\MompfdieTasks\\Tasks\\CleanupTask' -Name 'Enabled' -Value 1

Set-ItemProperty -Path 'HKCU:\\Software\\MompfdieTasks\\Tasks\\CleanupTask' -Name 'LogLevel' -Value 'Verbose'

```



\## 📦 Release Channel

This is a \*\*Release Candidate\*\* (`v1.0.0-rc1`).

A stable release will follow once the module is fully tested.



---



📁 Project: \[github.com/theMompfdie/mompfdie.coretools](https://github.com/theMompfdie/mompfdie.coretools)



License: Personal use permitted. Reuse/modification only allowed with permission from Raimund Pließnig.



---



> "Because logic and reuse make PowerShell more elegant."

