# Detection Engineering Lab: MITRE ATT&CK T1059.001 (PowerShell Mimikatz Execution)

## Overview
Engineered and validated a SIEM detection rule targeting adversary use of PowerShell for credential dumping and malicious script execution (T1059.001), specifically identifying Mimikatz activity.

## Environment Architecture
* **Target Endpoint**: Windows 11 Enterprise (`DESKTOP-COD3V74`)
* **Telemetry Collector**: Elastic Agent (Endpoint Security / Custom Logs)
* **SIEM Platform**: Elastic Cloud SIEM
* **Emulation Tool**: Atomic Red Team (`Invoke-AtomicTest T1059.001 -TestNumbers 1`)

## Detection Logic & Query
* **Rule Type**: Elasticsearch Query
* **Target Index Pattern**: `logs-*`
* **KQL Query**:
  ```kql
  *Mimikatz*
