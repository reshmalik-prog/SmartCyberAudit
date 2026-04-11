# Smart Cyber Audit - Backend Modules

This repository contains the core security logic for the **Smart Cyber Audit** tool. These modules handle vulnerability detection and system log analysis.

## Features
* **Port Scanner:** Detects open ports and identifies potential security risks (e.g., SMB/Port 445).
* **Log Analyzer:** Scans system audit logs for "FAILED" login attempts and critical alerts.
* **Process Monitor:** Identifies suspicious system processes or resource-heavy activities.
* **Automated Logging:** Maintains a persistent `audit_logs.txt` for all security events.

---

## 🛠️ Integration Guide (For UI/Dashboard Lead)
Use the following functions from `ReshmaModule` to populate the dashboard tabs:

| Feature | Function Call | Output Type |
| :--- | :--- | :--- |
| **Vulnerability Tab** | `scan_vulnerabilities()` | `List[String]` |
| **Log Analysis Tab** | `check_failed_logins()` | `String (Alert Count)` |
| **Audit Report** | `get_logs()` | `List[String] (Last 10 lines)` |

---

## Setup & Installation
If you are running this from the project ZIP, follow these steps:

1. **Install Dependencies:**
   ```bash
   pip install -r backend/requirements.txt
