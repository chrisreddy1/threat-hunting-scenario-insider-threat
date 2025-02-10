# Threat Hunt Report: Insider Data Exfiltration

## Platforms and Technologies Used
- **Operating System**: Windows 10 Virtual Machines (Microsoft Azure)
- **Endpoint Detection & Response (EDR)**: Microsoft Defender for Endpoint
- **Scripting & Query Language**: Kusto Query Language (KQL)
- **Steganography Tool**: Steghide.exe
- **Compression Utility**: 7zip

---

## Scenario
A corporate executive, **Bryce Montgomery**, at a large tech company is under investigation for potential intellectual property theft. The **Risk Department** suspects unauthorized access and data exfiltration. The **VP of Risk** has requested the **Security Operations Manager** to investigate any unusual activity or unauthorized data access associated with Bryce Montgomery's workstation.

### Important Context:
- **Administrative Privileges**: Executives, including Bryce Montgomery, have full administrative access to their workstations.
- **DLP Exemption**: While a **Data Loss Prevention (DLP)** solution is in place, certain executives are exempt due to productivity concerns.

### Known Information:
- **Username**: `bmontgomery`
- **Workstation**: `corp-ny-it-0334`

---

## Investigation Steps

### Step 1: Initial File Activity Analysis
Searched the **DeviceFileEvents** table for any corporate files accessed or modified by Bryce Montgomery.

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == 'corp-ny-it-0334'
| where InitiatingProcessAccountName == 'bmontgomery'
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

<img width="462" alt="query1" src="https://github.com/user-attachments/assets/2d95b597-5633-428f-8e42-3becd117914f" />


#### **Findings:**
- File SHA256 hash: `ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d`
- While this suggests file interaction, it's insufficient to confirm data exfiltration. He may have used another device or account.

---

### Step 2: Identifying Other Accounts & Workstations
Investigated whether other accounts or devices interacted with the same file.

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where SHA256 == 'ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d'
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName
| order by Timestamp asc
```

<img width="548" alt="query2" src="https://github.com/user-attachments/assets/71555a90-738a-4611-b61f-6db572f5c97d" />


#### **Findings:**
- The **'lobbyuser'** account on device **'lobby-fl2-ae5fc'** accessed the same file.
- The same files appeared on both Bryce's and the shared workstation:
  - `Q1-2025-ResearchAndDevelopment.pdf`
  - `Q2-2025-HumanTrials.pdf`
  - `Q3-2025-AnimalTrials-SiberianTigers.pdf`

---

### Step 3: Suspicious Tool Usage - Steghide
Detected the use of `steghide.exe`, which is commonly associated with **steganography** (hiding data within images).

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == 'lobby-fl2-ae5fc'
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="494" alt="query4" src="https://github.com/user-attachments/assets/bc7e1610-8e09-4bbd-98d5-79f842bfd7ba" />

#### **Findings:**
- **Steghide.exe** was executed on the shared workstation, indicating possible data concealment.
- Further analysis was needed to determine its purpose.

---

### Step 4: Confirming Steganographic Activity
Checked if company data was embedded into personal images.

#### **KQL Query Used:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "steghide.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

<img width="620" alt="query5" src="https://github.com/user-attachments/assets/8c903b6e-aae3-4c9d-aa92-b62517027448" />

#### **Findings:**
- Data was embedded into **bitmap images** found on Bryce’s machine.
- Retrieved images from Bryce’s personal folder:
  - [Image Evidence - Google Drive](https://drive.google.com/drive/u/2/folders/1oFsmQ14nkNUmexd7VFWegZ9FLKBINkc_)
- The images contained **pictures of Bryce and his family**, suggesting an attempt at concealment.

---

### Step 5: Evidence of Compression
Investigated whether the steganographic images were further processed (e.g., compressed or archived).

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where InitiatingProcessCommandLine contains ('suzie-and-bob.bmp')
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessSHA256
```

<img width="621" alt="query6" src="https://github.com/user-attachments/assets/a2a1b64d-3c27-4d43-ada1-3b892495926a" />

#### **Findings:**
- The images were archived into a **zip file**: `secure_files.zip`.
- **SHA-256 of the 7zip process**: `707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71`

---

### Step 6: File Manipulation & Renaming
Checked whether the zip file was renamed to avoid detection.

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where InitiatingProcessAccountName == 'lobbyuser'
| where InitiatingProcessAccountDomain == 'lobby-fl2-ae5fc'
| where ActionType == 'FileRenamed'
| where PreviousFileName == 'secure_files.zip'
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, PreviousFileName
```

<img width="440" alt="query8" src="https://github.com/user-attachments/assets/6e3d4c6c-dee2-4ed8-978d-303a06d34773" />

#### **Findings:**
- The zip file was renamed to **'marketing_misc.zip'**, likely to disguise its contents.
- However, we still needed conclusive proof that Bryce was behind this.

---

### Step 7: Conclusive Evidence Linking Bryce
Investigated whether **'marketing_misc.zip'** was moved to a location tied directly to Bryce.

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where FileName == 'marketing_misc.zip'
```

<img width="441" alt="query9" src="https://github.com/user-attachments/assets/9c7dbbce-cca0-440b-8daf-3a30f81f7805" />

#### **Findings:**
- The zip file was found in **Bryce’s personal file directory** at `2025-02-05T08:57:32.2582822Z`.
- This provides **conclusive evidence** that Bryce attempted to steal corporate data.

---

## **Conclusion**
### **Key Findings:**
- Bryce Montgomery interacted with sensitive corporate files.
- He likely used a **shared workstation** under a different account (**'lobbyuser'**) to obscure his actions.
- **Steghide.exe** was used to **embed corporate data** into images.
- The images were then **compressed into a zip file** and renamed for further obfuscation.
- **Final proof**: The stolen file (`marketing_misc.zip`) was located in Bryce’s personal directory.

### **Final Verdict:**
✅ **Bryce Montgomery is guilty of data exfiltration** using **steganography and file obfuscation techniques**.

### **Recommended Actions:**
1. **Immediate Termination & Legal Action** - Given the evidence, legal proceedings should be initiated.
2. **Revocation of Administrative Privileges** - Executives should no longer have unrestricted admin rights.
3. **DLP Policy Revision** - Remove DLP exemptions to prevent similar future incidents.
4. **Enhanced Monitoring** - Implement anomaly detection alerts for steganography tools like `steghide.exe`.

---

### **End of Report**
