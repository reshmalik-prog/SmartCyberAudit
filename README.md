# SmartCyberAudit: AI-Based Cybersecurity Auditing and Threat Detection System

> **Abstract**: SmartCyberAudit is an AI-powered desktop application built in Python designed to automate cybersecurity auditing and system monitoring. By integrating Machine Learning for anomaly detection and NLP for log analysis, the system identifies vulnerabilities, open ports, and suspicious activities such as brute force attempts. The tool streamlines the audit process by providing real-time visualizations and generating comprehensive AI-driven reports via LLaMA 3, enabling users to proactively strengthen their digital security posture.

### Project Members

1.  KHAN ALFIA SHAMSUL
2.  MALIK RESHMA SHAFAAT HUSAIN
3.  QURESHI AFIFA ARIF
4.  BELIM HAMZAH ASLAM

### Project Guides

1.  PROF. JUNAID MANDVIWALA [ Primary Guide ]

### Deployment Steps

Please follow the below steps to run this project.

1.  **Install Python**: Ensure Python 3.8 or higher is installed on your Windows system.
2.  **Setup Environment**: Clone the repository and install required dependencies using `pip install -r requirements.txt`.
3.  **Install Ollama**: Download and install Ollama, then pull the LLaMA 3 model (`ollama run llama3`) for AI insights.
4.  **Grant Permissions**: Run the terminal or IDE as **Administrator** to allow the tool to access firewall settings and network ports.
5.  **Launch Application**: Execute `python main.py` to start the Tkinter GUI.
6.  **Generate Report**: Perform the scan and click "Export Report" to save the findings in the `/reports` folder.

### Subject Details

  - **Class**: TE (AI\&DS) Div A - 2025-2026
  - **Subject**: Mini Project Lab: 2B (AI\&DS) (MP 2B (A)(R19))
  - **Project Type**: Mini Project

### Platform, Libraries and Frameworks used

1.  [Python](https://www.python.org/) (Core Programming Language)
2.  [Tkinter](https://docs.python.org/3/library/tkinter.html) (GUI Framework)
3.  [Scikit-learn](https://scikit-learn.org/) (Machine Learning & NLP)
4.  [Ollama / LLaMA 3](https://ollama.com/) (Local LLM Integration)
5.  [SQLite](https://sqlite.org/) (Audit History Database)
6.  [Matplotlib](https://matplotlib.org/) (Data Visualization)

### Dataset Used

1.  [Custom System Logs](https://www.google.com/search?q=https://github.com/SmartCyberAudit) (Internal log parsing for NLP training)
2.  [Isolation Forest Training Set](https://scikit-learn.org/stable/modules/outlier_detection.html) (Synthetic/Historical system behavior data)

### References

  - [Python psutil Documentation](https://psutil.readthedocs.io/)
  - [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
  - [Ollama API Integration Guide](https://github.com/ollama/ollama-python)

## License

This project is for educational purposes.
