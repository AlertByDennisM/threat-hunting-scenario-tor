
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/AlertByDennisM/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-17T18:11:15.0903895Z`. These events began at `2025-11-17T17:26:08.3599553Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "labuser710"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-17T17:26:08.3599553Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1155" height="418" alt="image" src="https://github.com/user-attachments/assets/0bfff52d-66d3-47da-8624-55fb02c94d1a">


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.1.exe". Based on the logs returned, at `2025-11-17T17:52:46.2159203Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-15.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.1 (1).exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1349" height="93" alt="image" src="https://github.com/user-attachments/assets/6c150935-31bd-4bbe-b47a-8237ad8271b1">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser710" actually opened the TOR browser. There was evidence that they did open it at `2025-11-17T17:53:57.7557486Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1363" height="441" alt="image" src="https://github.com/user-attachments/assets/10f438a6-5854-4bb2-bc6e-fcbf863b0625">


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-17T17:54:25.1832404Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `149.202.79.129` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser710\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1350" height="441" alt="image" src="https://github.com/user-attachments/assets/e0a5f1db-ea73-43b1-91af-99cce764668c">


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-11-17T17:26:08.3599553Z`
- **Event:** The user “labuser710” executed the installer “tor-browser-windows-x86_64-portable-15.0.1 (1).exe” from the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser710\Downloads\tor-browser-windows-x86_64-portable-15.0.1 (1).exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-11-17T17:53:57.7557486Z`
- **Event:** User labuser710 executed the installer tor-browser-windows-x86_64-portable-15.0.1 (1).exe located in C:\Users\labuser710\Downloads\. The command line included "/S", indicating a silent installation.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.1 (1).exe /S`
- **File Path:** `C:\Users\labuser710\Desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-11-17T17:54:25Z`
- **Event:** User "labuser710" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\labuser710\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-11-17T17:54:25.1832404Z`
- **Event:** A network connection to IP `149.202.79.129` on port `9001` by user "labuser710" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser710\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-11-17T17:55:22.0362121Z` - Connected to `45.14.233.193` on port `443`.
  - `2025-11-17T17:54:31.3362083Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser710" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

User labuser710, on device threat-hunt-lab, downloaded and silently installed the portable version of Tor Browser (tor-browser-windows-x86_64-portable-15.0.1 (1).exe) from the Downloads folder. Shortly thereafter, the Tor Browser executable (tor.exe) was launched, and an outbound connection was established to a remote IP address (149.202.79.129) in France on port 9001—a port commonly used by Tor network nodes. Within the same session, numerous “tor-” prefixed files were copied to the Desktop and a file named tor-shopping-list.txt was created. The use of /S for silent install, the direct outbound connection to a known hosting provider’s IP, the file copying, and the creation of a desktop file all combine to show a pattern of covert or bulk usage of Tor Browser, outside of typical benign user behavior.

---

## Response Taken

TOR usage was confirmed on endpoint threat-hunt-lab. The device was isolated and the user's direct manager was notified.

---
