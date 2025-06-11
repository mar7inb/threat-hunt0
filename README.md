# threat-hunt0 - Deep Access: The Adversary

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

**Objective:** Initial signs of PowerShell being used in a way that deviates from baseline usage. Look for PowerShell actions that started the chain.


## Query:
```kql
DeviceProcessEvents
| where InitiatingProcessFileName has "powershell"
| where AccountName == "acolaight"
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

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where Timestamp <= datetime(2025-05-25T09:14:05.0880043Z)
```

I already knew the earliest time this machine started showing activity, so I used that timestamp to filter the query. This helped me find the earliest registry events tied to the attack, allowing me to pinpoint where the initial changes began.



![image](https://github.com/user-attachments/assets/bedd9c92-bbce-4aa4-b129-6abea287422a)









  
