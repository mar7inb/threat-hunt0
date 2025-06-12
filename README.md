# threat-hunt-0 - Deep Access: The Adversary


![image](https://github.com/user-attachments/assets/f04b566d-a31b-4e26-b81c-ce1ff666fe29)

# Scenario:

Multiple organizations across Southeast Asia and Eastern Europe observed coordinated, stealthy activity involving PowerShell bursts, registry changes, and leaked credentials mimicking red-team tools. Despite no alerts triggering, evidence points to a long-term, targeted campaign — possibly by a revived threat group or mercenaries — leveraging supply chain access to exfiltrate sensitive data across sectors. Two compromised machines may hold the key to uncovering the full scope. Virtual machines were created around May 24th, 2025. These systems were active for only a few hours before deletion, suggesting minimal logging and potential use as entry points.


## Identifying the device in question: 

## Query:
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-05-23) .. datetime(2025-05-26))
| summarize 
    FirstSeen=min(Timestamp), 
    LastSeen=max(Timestamp), 
    ProcessCount=count() 
    by DeviceId, DeviceName
| take 100
```

## Device in question
  **acolyte756**

![image](https://github.com/user-attachments/assets/60d6a167-3975-484e-b679-5d66fc0430b6)


Why is this the device in question? Because it doesn't follow our organizations naming standard "vm-(user initial)-(device type)"



## Flag 1 - Initial Powershell Execution 

**Objective:** Initial signs of PowerShell being used in a way that deviates from baseline usage. I searched for PowerShell actions that started the chain.


## Query:
```kql
DeviceProcessEvents
| where InitiatingProcessFileName has "powershell"
| where DeviceName == "acolyte756"
| sort by Timestamp asc
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

Earliest powershell activity: 


![image](https://github.com/user-attachments/assets/88502ed3-599b-4e04-9b2f-c10ca6a771bc)



## Flag 2 - Suspicious outbound signal 

**Objective:** External destinations unrelated to normal business operations. When machines talk out of turn, it could be a sign of control being handed off.

## Query:
```kql
DeviceNetworkEvents
| where DeviceName == "acolyte756"
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| extend RemoteDomain = tostring(RemoteUrl)
| where not(RemoteDomain has_any ("microsoft.com", "google.com", "yourcompany.com"))
| project Timestamp, DeviceName, RemoteIP, RemoteDomain, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

This query examines outbound network connections from the device acolyte756, specifically focusing on successful connections to public IPs or domains. It filters out known safe domains (like Microsoft, Google, or internal company ones) to isolate potentially suspicious or unknown external communication. By projecting key details—such as remote IPs, ports, protocols, and the initiating process—it helps identify whether the device contacted unfamiliar or malicious infrastructure, which could indicate command-and-control activity or data exfiltration. Sorting by most recent events puts the latest suspicious connections at the top for immediate review.

**Unusual outbound connection:**


![image](https://github.com/user-attachments/assets/da98dbf0-6ca5-4317-ac6f-d6528fa94595)


## Flag 3 – Registry-based Autorun Setup

**Objective:** Detect whether the adversary used registry-based mechanisms to gain persistence. Registry is a favored place to hide re-execution logic — it’s reliable, stealthy, and usually overlooked.

## Query:

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where ActionType == "RegistryValueSet"
```

**file associated with the newly created registry value** 


![image](https://github.com/user-attachments/assets/6daed87a-f023-42f3-8373-c5031578e54f)

This query filters DeviceRegistryEvents to show all registry value creation events (ActionType == "RegistryValueSet") that occurred on the device "acolyte756". It narrows the results to only the relevant machine and action type, helping isolate any unauthorized or suspicious registry modifications.


Finding a C2.ps1 (Command and Control) script on a machine usually means the system has been compromised and is actively communicating with or awaiting commands from a remote attacker. So this was the giveaway. 


## Flag 4 – Scheduled Task Persistence

**Thought:** Adversaries rarely rely on just one persistence method. Scheduled tasks offer stealth and reliability — track anomalies in their creation times and descriptions


## Query:
```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where Timestamp <= datetime(2025-05-25T09:14:05.0880043Z)
```

I already knew the earliest time this machine started showing activity, so I used that timestamp to filter the query. This helped me find the earliest registry events tied to the attack, allowing me to pinpoint where the initial changes began.



![image](https://github.com/user-attachments/assets/bedd9c92-bbce-4aa4-b129-6abea287422a)


HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task


## Flag 5 – Obfuscated PowerShell Execution

**Objective:** Uncover signs of script concealment or encoding in command-line activity. I had to look for PowerShell patterns that don't immediately reveal their purpose. 


## Query:
```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-version 2", 
    "-executionpolicy bypass", 
    "-executionpolicy unrestricted", 
    "-nop", "-noprofile", 
    "-windowstyle hidden", 
    "-w hidden", 
    "-noninteractive", 
    "-enc", "-encodedcommand"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/6591c1e2-4e01-4742-8722-fd064dff3398)

I found this execution made by the user "acolaight" - "powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA
The attacker 

## Flag 6 – Obfuscated PowerShell Execution

Attackers sometimes use outdated script configurations to bypass modern controls. Modern defenses can sometimes only detect modern behavior. The previous query (with the help of ChatGPT, it was created) already helped us identify the outdated process. 
"-version2" 

![image](https://github.com/user-attachments/assets/ed86bfb6-a403-405e-b58d-a51e0f22bf62)


"powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit

Kind of an obvious one as Powershell's current version is 7.4. - A quick Google search helped me find this out. 



## Flag 7 – Remote Movement Discovery


An attacker will always want to gain more access once they are successful in the initial breach. The attacker was successful in downgrading powershell versions, so a powershell execution was expected. 

```kql
DeviceProcessEvents
| where ProcessCommandLine has "schtasks.exe"
| where DeviceName == "acolyte756"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| sort by Timestamp desc
```

We’d want to consider looking for schtasks.exe based on previous behavior because:

PowerShell activity was already observed, suggesting possible script-based execution.

The presence of registry modifications (like entries under TaskCache or Run) implies a scheduled task or persistence mechanism may have been set up.

Attackers often use schtasks.exe in tandem with PowerShell to automate execution of payloads like C2.ps1.


![image](https://github.com/user-attachments/assets/d47d4307-6777-48fd-8d3f-0e6169d77c24)


The attacker was able to get access to "victor-disa-vm"


## Flag 8 and 8.1 – Entry Indicators on Second Host and Persistence Registration on Entry

I noticed a pattern that this attacker used the word "sync" so when I analyzed "victor-disa-vm" I looked for file names that conatined "sync". Attackers use keywords like these because they sound "routine" to corporate environments. 

## Query:
```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where FileName has_any ("sync", "save")
| take 100
```

This query helped me find: 

![image](https://github.com/user-attachments/assets/f66b6f69-b2c1-433b-a160-6284c3d39eff)


savepoint_sync.lnk - was the lateral entry point. - .lnk files can point to and silently execute other scripts, executables, or remote payloads. Attackers often use them as:

Droppers or launchers for malicious tools.

Disguised links that look like legitimate shortcuts but lead to attacker-controlled scripts or shares.


The attacker at this point was also going to mess with the computer's registry values so I then looked for suspicious persistence registration. 

## Query:
```kql
DeviceRegistryEvents
| where DeviceName == "victor-disa-vm"
| where RegistryValueData contains "sync" or RegistryKey contains "sync"
```

![image](https://github.com/user-attachments/assets/1b13d551-ad94-477d-9ff9-a0276d482eca)


Registry value associated with persistence: powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"


## Flag 9 - External Communication Re-established


The attacker was most likely going to exeternally communicate again just like how he did on his initial breach. 

```kql
DeviceNetworkEvents
| where DeviceName == "victor-disa-vm"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe")
    or InitiatingProcessCommandLine has_any ("http", "https", "wget", "Invoke-WebRequest", "curl", "tcp", "443", "nc", "netcat")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    InitiatingProcessAccountName
| order by Timestamp asc
```

This query helped me identify the same domain they reached out to initially "pipedream.net" = eo1v1texxlrdq3v.m.pipedream.net


![image](https://github.com/user-attachments/assets/19461c74-9214-4039-b729-5dbc45059e63)

"tcp", "443", "nc" (common in beaconing or tunneling)


## Flag 10 – Stealth Mechanism Registration


Some attackers don’t need to schedule a task or add something to the registry to stay on a system. Instead, they use a hidden Windows feature called WMI (Windows Management Instrumentation). With WMI, they can tell Windows:

“If X happens (like the system boots up or a user logs in), automatically run this code.”

That means the attacker’s script or payload runs automatically without needing to interact with the system again. It’s stealthy, because it doesn’t use the more obvious signs of persistence like scheduled tasks or startup folders.


## Query:
```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has "beacon"
   or FileName has "beacon"
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp asc
```

This query makes sense because it helps identify suspicious processes related to command-and-control (C2) activity — specifically those that include the term "beacon," which is commonly used in attacker tooling. And it was part of the flag hint. 

![image](https://github.com/user-attachments/assets/7aec76c9-8e95-4ea0-8bed-2d546304cfde)

Earliest activity time tied to WMI persistence: 2025-05-26T02:48:07.2900744Z - May 25, 2025 7:08:09 PM


## Flag 11 – Suspicious Data Access Simulation

Mimikatz are widely used by attackers to steal credentials from Windows systems. Mimikatz and its variations often leave distinct traces—such as access to password storage files, credential caches, or security-related system secrets.

I decided to take kind of a wildcard approach to this one and use the following query to find the Mimikatz, probably not to most accurate but it worked. 

## Query:
```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine contains "mimi"
```

I was able to find the file deployed to attempt credential dumping. 

![image](https://github.com/user-attachments/assets/48f926e5-5f98-4f90-8d47-625d5feef865)


## Flag 12 – Unusual Outbound Transfer

The goal was to detect data transfers to untrusted cloud or file-sharing services. Attackers often use familiar sites to hide activity, so tracking connections and the SHA256 of involved processes helps identify the exact tools used.

Why the query helped: It finds network connections to suspicious domains and links them to the responsible processes by their SHA256 hash, enabling precise tracking of malicious files.


```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          SHA256
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/17591eaf-5b24-442c-b1e8-6f6c386202da)


## Flag 13 – Sensitive Asset Interaction

The goal was to uncover if any important internal documents, especially time-sensitive or critical project files, were accessed. Monitoring access logs helps reveal not just file views but the attacker’s intent, with a focus on documents tied to year-end projects, as per the Organization's suspicion. 

## Query:
```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has_any ("2025-12", "2025_12", "2025.12") 
| order by Timestamp asc
```
This query helped me find:
![image](https://github.com/user-attachments/assets/4b3e0b61-45f7-4d73-9a28-f2511e80dac9)



## Flag 14 – Sensitive Asset Interaction

looking for the specific command used to compress the malicious tool—likely a sign of staging for exfiltration or lateral movement.


## Query:
```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where ActionType == "FileCreated"
| where FolderPath has_any (
    "C:\\Users\\Public\\",
    "C:\\ProgramData\\",
    "C:\\Users\\",
    "C:\\Temp\\",
    "C:\\Windows\\Temp\\"
)
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
    or FileName endswith ".cab"
    or FileName endswith ".tar"
| project Timestamp,
          DeviceName,
          FileName,
          FolderPath,
          InitiatingProcessAccountName,
          InitiatingProcessCommandLine,
          SHA256
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/72b4e198-fe90-4bc3-94f4-0e27070bda96)


What the attacker did:
Used PowerShell to run a script without user profiles (-NoProfile) and bypassed execution policy restrictions (-ExecutionPolicy Bypass), which are common tactics to avoid detection and security controls.

Compressed a folder named dropzone_spicy located in the public directory.

Created a ZIP file called spicycore_loader_flag8.zip, also in a public directory—an unusual place for legitimate compression activity.

This likely staged tools or exfiltration data, prepping it for movement either to another host or outside the network.

Why the query helped:
The KQL query filtered for:
Newly created compressed files (.zip, .rar, etc.)
Non-administrative locations commonly abused by attackers (C:\Users\Public\, C:\Temp\, etc.)
This approach zeroed in on compression events in suspicious paths—exactly where and how attackers stage malicious payloads for lateral movement or exfiltration. The PowerShell command stood out clearly due to its syntax and location, revealing part of the attacker’s toolchain and intent.


## Flag 15 – Deployment Artifact Planted

The goal is to confirm if payloads were saved to disk by looking for unusual compressed files in shared or public directories. These staged files may not have been executed yet, but they signal upcoming malicious activity.

I used the same query it had already identified the compressed file: spicycore_loader_flag8.zip


## Flag 16 – Persistence Trigger Finalized

The goal was to identify the last scheduled task configured to run suspicious or newly dropped content — particularly scripts or executables with uncommon or non-standard names.

## Query:
```kql
DeviceProcessEvents
| where InitiatingProcessAccountName == "v1cth0r"
| where ProcessCommandLine has_any ("schtasks", "ScheduledTasks")
| where ProcessCommandLine has_any (".ps1")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

This query helped me pinpoint the exact time when the user v1cth0r executed a scheduled task related to a PowerShell script. By filtering for process commands that included both "schtasks" and PowerShell script extensions (".ps1"), I focused on scheduled task creations or modifications involving suspicious scripts. Sorting the results by timestamp ascending allowed me to identify the earliest occurrence of such activity, leading me to the specific timestamp **2025-05-26T07:01:01.6652736Z**, which marks a likely moment when the attacker set up automation to run malicious content. I basically used previous hints to formulate the query and paid attention to the attackers habits. 

![image](https://github.com/user-attachments/assets/2d3233ff-b0bd-4836-a635-495de2131a05)

| Technique ID | Technique Name                                | Description                                                       |
|--------------|-----------------------------------------------|-------------------------------------------------------------------|
| T1059        | Command and Scripting Interpreter             | Use of PowerShell, CMD, WMIC, Rundll32, Mshta to execute commands or scripts. |
| T1071.001    | Application Layer Protocol: Web Protocols     | Use of HTTP/S protocols for command and control or data transfer. |
| T1105        | Ingress Tool Transfer                         | Use of utilities like wget, curl, Invoke-WebRequest to download tools or payloads. |
| T1027        | Obfuscated Files or Information               | Use of encoded or obfuscated command lines to evade detection.   |
| T1041        | Exfiltration Over C2 Channel                   | Use of outbound network connections to exfiltrate data.          |
| T1070.004    | Indicator Removal on Host: File Deletion      | (Implied) Use of date-based filenames for cleanup or staging.    |



# Lessons Learned

- Attackers often abuse built-in Windows tools like PowerShell, CMD, WMIC, Rundll32, and Mshta to execute commands and communicate over the network, making detection harder.
- Monitoring command lines for suspicious keywords such as URLs, IP addresses, or common network utilities (`wget`, `curl`, `Invoke-WebRequest`) is essential for identifying potentially malicious activity.
- Date-based patterns in filenames or command arguments can indicate attacker staging, persistence, or automated tasks.
- Correlating process execution with network connections and user accounts provides valuable context to investigate suspicious behaviors and build a timeline.
- Narrowing analysis to specific devices reduces noise and helps focus threat hunting efforts effectively.


  
