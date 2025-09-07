# 🕵️‍♂️ Real-Time Network Packet Sniffer with Alert System

A powerful Python-based packet sniffing tool with live traffic analysis, anomaly detection (port scans, flooding), credential sniffing, DNS logging, and an intuitive GUI built using Tkinter and ttkbootstrap.

![Screenshot 2025-06-27 155909](https://github.com/user-attachments/assets/0c54e133-7172-48e2-9020-5397d48cee46)


---

## 📌 Features

- 📡 **Real-Time Packet Sniffing** with Scapy
- 📊 **Live Dashboard** with protocol & port usage graphs
- ⚠️ **Anomaly Detection** for:
  - Port Scans (10+ ports in 10s)
  - Flooding (100+ packets in 10s)
- 🧠 **Credential Sniffing** (toggleable)
- 🌐 **DNS Query Logging**
- 🗃️ **SQLite Logging** for packets, DNS, and credentials
- 📨 **Email Alerts** via SMTP
- 🔐 **Settings Panel** to enable/disable sniffing features
- 🧾 **Search & Export Logs** (CSV format)
- 🖥️ **Modern GUI** with ttkbootstrap

---

## 🧰 Tech Stack

- Python 3.10+
- [Scapy](https://scapy.net/)
- Tkinter + ttkbootstrap
- Matplotlib
- SQLite
- smtplib + dotenv

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/network-sniffer-alert-system.git
cd network-sniffer-alert-system
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Setup .env for Email Alerts

```bash
EMAIL_SENDER=youremail@example.com
EMAIL_PASSWORD=yourapppassword
EMAIL_RECEIVER=admin@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
```
⚠️ Use App Passwords for Gmail or provider-specific SMTP.

### 4. Run the App

```bash
python main.py
```

## 📁 Project Structure

```bash
network-sniffer-alert-system/
├── app/
│   ├── gui.py                 # GUI and dashboard logic
│   ├── sniffer.py             # Packet sniffing & detection engine
│   └── utils/                 # Optional helper modules
├── main.py                    # Entry point for GUI
├── .env                       # Email credentials (excluded in .gitignore)
├── requirements.txt
└── README.md
```

## 🛡️ Future Improvements
- IP blocking / firewall integration
- Slack or webhook alerts
- GeoIP mapping
- Advanced rule-based anomaly engine
- CLI-only mode (optional)

## 🧪 Testing
### Basic functionality can be tested using:

```bash
ping google.com
nslookup example.com
curl -d "username=admin&password=1234" http://test.local/login
```

## 📦 Packaging
### Use PyInstaller to create a standalone .exe:

```bash
pyinstaller --onefile --windowed main.py
```

## 📄 License
### MIT License © 2025 [Pradeep Behera]

## 🙋‍♂️ Contribution
### Pull requests and issues welcome! Please fork the repo and submit PRs for improvements or bug fixes.



