Cyber Audit Tool — AI + NLP 

A desktop-based cybersecurity auditing application developed in Python. The tool analyzes system security, detects vulnerabilities, and provides intelligent insights using Machine Learning and Natural Language Processing techniques.

Overview

The Cyber Audit Tool is designed to perform comprehensive system analysis by combining traditional security checks with modern AI-based techniques. It evaluates system configurations, monitors activity, identifies vulnerabilities, and generates structured audit reports.

Features
System Analysis
Displays CPU, RAM, disk, and network usage
Retrieves system information such as OS, uptime, and active users
Lists installed software
Security Checks
Firewall status verification
Antivirus detection
User Account Control (UAC) status
Windows update status
Computes an overall security score
Vulnerability Detection
Scans for open ports
Classifies risks as Low, Medium, or High
Identifies high-risk ports
Provides option to block vulnerable ports
Machine Learning Integration
Uses Isolation Forest for anomaly detection
Learns system behavior from historical scans
Identifies abnormal patterns in system performance
Log Analysis using NLP
Processes system logs using:
TF-IDF Vectorization
Multinomial Naive Bayes Classifier
Detects events such as:
Login failures
Brute force attempts
Privilege escalation
Suspicious processes
Visualization
Displays trends for CPU usage, RAM usage, and risk score
Provides historical analysis of system behavior
AI-Based Insights
Integrates with a local language model (LLaMA 3 via Ollama)
Generates concise explanations including:
Identified issues
Associated risks
Recommended actions
Report Generation
Generates a complete audit report
Includes NLP-based log summaries
Provides actionable recommendations
Technology Stack
Programming Language: Python
GUI Framework: Tkinter
Machine Learning: scikit-learn (Isolation Forest)
Natural Language Processing: TF-IDF, Multinomial Naive Bayes
Visualization: Matplotlib
System Monitoring: psutil
Database: SQLite
AI Integration: Ollama (LLaMA 3)
Installation
Clone the Repository
git clone https://github.com/your-username/cyber-audit-tool.git
cd cyber-audit-tool
Install Dependencies
pip install -r requirements.txt
Install Ollama (Optional for AI Insights)

Download from: https://ollama.com/

Run the model:

ollama run llama3
Running the Application
python main.py
Working Principle
The user initiates a system scan
The application collects system and security data
Machine learning analyzes system behavior
NLP processes and classifies log entries
AI module generates insights
A structured audit report is produced
Machine Learning and NLP Details
Isolation Forest
An unsupervised learning algorithm
Detects anomalies based on deviations from normal behavior
Improves accuracy as more scan data is collected
NLP Pipeline
Converts textual logs into numerical form using TF-IDF
Applies Naive Bayes classification
Categorizes logs into meaningful security events
Project Structure
├── main.py              # Main application file
├── logs.txt             # Runtime logs
├── audit_history.db     # SQLite database
├── requirements.txt     # Project dependencies
├── README.md            # Documentation
Requirements
Python 3.8 or higher
Windows operating system (recommended for full functionality)
Administrative privileges (required for certain security operations)
Ollama (optional, for AI-based insights)
Limitations
Port scanning is limited to predefined common ports
Full functionality is optimized for Windows systems
Machine learning model requires multiple scans for effective results
AI insights depend on local model availability
Future Enhancements
Real-time monitoring capabilities
Web-based interface
Advanced threat detection mechanisms
Cloud integration
Cross-platform support
Author
Developed as part of a cybersecurity and artificial intelligence academic project.
License
This project is intended for educational purposes only.


