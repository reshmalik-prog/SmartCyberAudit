# SmartCyberAudit 

Cyber Audit Tool is a desktop-based cybersecurity application built in Python that analyzes system security, detects vulnerabilities, and provides intelligent insights using Machine Learning and NLP.

## Features

### System Analysis

* CPU, RAM, Disk, Network monitoring
* OS details, uptime, active users
* Installed software listing

### Security Checks

* Firewall status
* Antivirus detection
* UAC status
* Windows Update check
* Security score calculation

### Vulnerability Detection

* Open port scanning
* Risk classification (Low / Medium / High)
* High-risk port detection
* Option to block ports

### AI & Machine Learning

* Isolation Forest for anomaly detection
* Learns system behavior over time
* Detects unusual activity

### Log Analysis (NLP)

* TF-IDF + Naive Bayes
* Detects:

  * Login failures
  * Brute force attempts
  * Privilege escalation
  * Suspicious processes

### Visualization

* CPU, RAM, and Risk trends
* Historical system analysis

### AI Insights

* LLaMA 3 (via Ollama) integration
* Generates:

  * Issues
  * Risks
  * Recommendations

### Report Generation

* Export full **Word (.docx) audit report**
* Includes AI + NLP analysis

## Technologies Used

* Python
* Tkinter (GUI)
* Scikit-learn (ML)
* NLP (TF-IDF, Naive Bayes)
* Matplotlib
* SQLite
* psutil
* Ollama (LLaMA 3)

## Project Structure

```bash
SmartCyberAudit/
│── main.py
│
├── database/
│   └── audit_history.db
│
├── logs/
│   └── logs.txt
│
├── reports/
│   └── Cyber_Audit_report.docx
|
└── README.md
```

## Contributing

Contributions are welcome!

* Fork the repo
* Create a new branch (`feature-branch`)
* Commit your changes
* Push and create a pull request

## Requirements

* Python 3.8+
* Windows OS (recommended)
* Admin access for full features
* Ollama (optional for AI insights)

## Future Improvements

* Real-time monitoring
* Web dashboard
* Advanced threat detection
* Cloud integration

## Author

**Malik Reshma Shafaat Husain**
**Belim Hamzah Aslam**
**Khan Alfia Shamsul**
**Afifa Qureshi Arif**

## License

This project is for educational purposes.



SmartCyberAudit: AI-Based Cybersecurity Auditing and Threat Detection System
Abstract: SmartCyberAudit is an AI-powered desktop application built in Python designed to automate cybersecurity auditing and system monitoring. By integrating Machine Learning for anomaly detection and NLP for log analysis, the system identifies vulnerabilities, open ports, and suspicious activities such as brute force attempts. The tool streamlines the audit process by providing real-time visualizations and generating comprehensive AI-driven reports via LLaMA 3, enabling users to proactively strengthen their digital security posture.

Project Members
KHAN ALFIA SHAMSUL [ Team Leader ]

MALIK RESHMA SHAFAAT HUSAIN

QURESHI AFIFA ARIF

BELIM HAMZAH ASLAM

Project Guides
PROF. JUNAID MANDVIWALA [ Primary Guide ]

Deployment Steps
Please follow the below steps to run this project.

Install Python: Ensure Python 3.8 or higher is installed on your Windows system.

Setup Environment: Clone the repository and install required dependencies using pip install -r requirements.txt.

Install Ollama: Download and install Ollama, then pull the LLaMA 3 model (ollama run llama3) for AI insights.

Grant Permissions: Run the terminal or IDE as Administrator to allow the tool to access firewall settings and network ports.

Launch Application: Execute python main.py to start the Tkinter GUI.

Generate Report: Perform the scan and click "Export Report" to save the findings in the /reports folder.

Subject Details
Class: TE (AI&DS) Div A - 2025-2026

Subject: Mini Project Lab: 2B (AI&DS) (MP 2B (A)(R19))

Project Type: Mini Project

Platform, Libraries and Frameworks used
Python (Core Programming Language)

Tkinter (GUI Framework)

Scikit-learn (Machine Learning & NLP)

Ollama / LLaMA 3 (Local LLM Integration)

SQLite (Audit History Database)

Matplotlib (Data Visualization)

Dataset Used
Custom System Logs (Internal log parsing for NLP training)

Isolation Forest Training Set (Synthetic/Historical system behavior data)

References
Python psutil Documentation

NIST Cybersecurity Framework

Ollama API Integration Guide
