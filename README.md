# 🔐 Zero-Budget IP Threat Intelligence Engine

> One IP. One Verdict. Instant Threat Intelligence.

A modular, stateless IP Threat Intelligence Enrichment Engine that aggregates data from multiple open-source intelligence platforms and produces a unified, decision-ready risk assessment.

---

## 🚀 Features

- 🔎 IP enrichment from:
  - VirusTotal
  - AbuseIPDB
  - AlienVault OTX
- 🧠 Unified risk scoring engine
- 📊 Structured JSON API output
- 🖥️ Analyst-friendly CLI report mode
- ⚡ Zero paid infrastructure
- 🧩 Modular production-style architecture
- 🔐 Secure environment-based API key management
- ⏱️ Built-in free-tier rate limiting

---

## 🏗 Architecture

Client (CLI / API)  
↓  
Pipeline Controller  
↓  
VirusTotal → AbuseIPDB → OTX  
↓  
Risk Scoring Engine  
↓  
Structured Report Output  

Stateless design. No database. In-memory processing only.

---

## 🛠 Tech Stack

- Python 3.10+
- FastAPI
- Requests
- Modular service architecture

---

## ⚙️ Setup Instructions

### 1️⃣ Clone Repository

```bash
git clone <your-repo-url>
cd ip-threat-intel


2️⃣ Create Virtual Environment
python -m venv venv

Activate:

Windows

venv\Scripts\activate



3️⃣ Install Dependencies
pip install -r requirements.txt

🔑 API Key Setup

Create free accounts and generate API keys:

https://www.virustotal.com

https://www.abuseipdb.com

https://otx.alienvault.com

Set environment variables:

Windows (PowerShell)

$env:VIRUSTOTAL_API_KEY="your_key"
$env:ABUSEIPDB_API_KEY="your_key"
$env:OTX_API_KEY="your_key"



🖥 CLI Usage
python app.py 8.8.8.8

Example Output:

==================================================
        ZERO-BUDGET IP THREAT INTEL REPORT
==================================================
IP Address: 8.8.8.8
...
