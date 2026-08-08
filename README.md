# Automated Reconnaissance Tool with Python

A Python-based graphical user interface (GUI) application designed to automate the reconnaissance phase in ethical hacking and cybersecurity assessments. It aggregates target intelligence such as WHOIS data, DNS records, SSL certificates, server headers, admin panel discovery, and Shodan OSINT data into a unified dashboard and exports structured PDF reports.

![App Screenshot](background.jpg)

---

## 🚀 Key Features

* **Target Geolocation & IP Resolution:** Resolves target domain IP addresses and retrieves server geographic location data via `ipinfo.io`.
* **WHOIS Lookup:** Gathers domain registration details, registrar contact information, and creation/expiry dates.
* **DNS Record Enumeration:** Queries and displays essential DNS records (`A`, `MX`, `NS`, `TXT`).
* **SSL Certificate Inspection:** Parses SSL/TLS certificates for Common Name (CN), issuer info, and validity periods.
* **Web Reconnaissance:** Scans for standard endpoints like `robots.txt`, `sitemap.xml`, and common admin portal paths.
* **Shodan OSINT Integration:** Interrogates Shodan's API for exposed ports, running services, and device banners.
* **PDF Report Generation:** Exports scan results into a clean, formatted PDF document with timestamped logs.
* **Cyberpunk GUI Dashboard:** Built with Tkinter featuring custom styled dark mode and Matrix-themed aesthetics.

---

## 🛠️ Prerequisites

* Python **3.8+** installed on your system.

---

## 📦 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/automated-recon-tool.git
   cd automated-recon-tool
   ```

2. **(Optional) Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🖥️ Usage

Run the main application:
```bash
python recon.py
```

1. Enter the target domain (e.g., `example.com`) in the input box.
2. Click **Start Recon** to begin automated information gathering.
3. Review findings in the interactive terminal display window.
4. Click **Export PDF** to save the scan output as a PDF report.
5. Click **Clear Output** to reset the display for a new scan.

---

## 📁 Repository Structure

```text
├── recon.py          # Main Python application source code & GUI
├── background.jpg    # GUI background image asset
├── requirements.txt  # Python package dependencies
├── .gitignore        # Git ignore rules for Python builds & temp files
└── README.md         # Project documentation
```

---

## ⚠️ Disclaimer

This tool is created for **educational and authorized ethical security testing purposes only**. Scanning target systems without prior explicit consent is illegal. The author assumes no responsibility for misuse or damage caused by this software.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
