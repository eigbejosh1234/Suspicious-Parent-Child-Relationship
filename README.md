# Suspicious-Parent-Child-Relationship
A suspicious process with an uncommon parent-child relationship was detected in your environment.
**NOTE:** The alert below is real and it generated fron (Tryhackme), investigated by me.

**ALERT**
* datasource: sysmon
* timestamp: 06/11/2026 12:23:22.501
* event.code: 1
* host.name: win-3459
* process.name: TrustedInstaller.exe
* process.pid: 3577
* process.parent.pid: 3506
* process.parent.name: services.exe
* process.command_line: C:\Windows\servicing\TrustedInstaller.exe
* process.working_directory: C:\Windows\system32\
* event.action: Process Create (rule: ProcessCreate)

  **STEP 1 VERIFY IF THE ALERT APPEARS IN SPLUNK. I RAN:** <br>
  index=main process.name:TrustedInstaller.exe
  <img width="739" height="240" alt="image" src="https://github.com/user-attachments/assets/1f663e41-bea3-496d-9390-a7e45f951eb9" />
<img width="756" height="269" alt="image" src="https://github.com/user-attachments/assets/c38bb030-eb44-4b64-bf69-6d3dbaf60a67" />
The event image above two different hosts. <Br>
  **Host.name:** win-3449 <BR>
  **host.name**: win-3459 <br>
  * They both have same Process.name: TrustedInstaller.exe <br>
  * They both have same Process.parent.name: service.exe <br>
  * They both have same process.command_line: C:\Windows\servicing\TrustedInstaller.exe <br>
  * They both have same process.working_directory: C:\Windows\system32\ <br>
  * Time for host.name=win-3459: 6/11/26 11:23:09.501 AM <br>
  * Time for host.name=win-3449: 6/11/26 11:49:22.501 AM <br>
 
    From the investigation above, Everything currently looks normal because C:\Windows\servicing\TrustedInstaller.exe This is the expected location for TrustedInstaller.

    **Legitimate Parent**<br>
services.exe <br>
Windows services commonly launch TrustedInstaller.

**Multiple Hosts**<br>
The activity occurred on: <br>
win-3449 <br>
win-3459

When the same activity appears on multiple systems around the same time, it often indicates a Windows update or servicing task rather than malware targeting a single machine.

**STEP 2 WHAT HAPPENED AFTER TrustedInstaller.exe STARTED? I RAN**<br>
index=main TrustedInstaller.exe <br>
| table _time host.name process.name process.command_line process.parent.name
<img width="960" height="254" alt="image" src="https://github.com/user-attachments/assets/dfa136a2-6112-4e7c-a918-8f8a752d6047" />

* Process name: TrustedInstaller.exe <br>
Legitimate Windows component.

* Path: C:\Windows\servicing\TrustedInstaller.exe <br>
This is the correct Microsoft location.

* Parent process: services.exe <br>
This is a normal system service launcher.

**STEP 3 BEHAVIOR COMPARISM**
Both events are: <BR>
Same process <br>
Same command line <br>
Same parent process <br>
Different hosts <br>
Different timestamps

This pattern strongly suggests: <br>
Windows servicing / update activity running across multiple machines

**STEP 4 CHECK FOR NEW USER CREATION: I RAN:** <BR>
index=main TrustedInstaller.exe EventCode=4720 <BR>
| table _time host user TargetUserName SubjectUserName
<img width="960" height="338" alt="image" src="https://github.com/user-attachments/assets/26453920-6d6f-4770-b2bd-66fc9059afab" />
This image indicated that Most likely scenario: Windows maintenance activity Because: <br>
TrustedInstaller runs during Windows updates <br>
No account creation events detected <br>
No privilege escalation evidence yet.

**FINAL TRIAGE DECISION: BENIGN** <br>
Activity is consistent with normal Windows servicing operations. No indicators of compromise identified.
