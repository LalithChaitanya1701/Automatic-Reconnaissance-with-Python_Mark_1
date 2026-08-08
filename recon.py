import socket
import ssl
import whois
import dns.resolver
import requests
import shodan
import os
import OpenSSL
import tkinter as tk
from fpdf import FPDF
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk

# Initialize main window
window = tk.Tk()
window.title("AUTOMATED RECON TOOL")
window.geometry("1000x650")
window.resizable(False, False)
window.configure(bg="#0a0a0a")

# Load and scale background image
bg_img = Image.open("background.jpg") 
bg_img = bg_img.resize((1000, 650))
bg_photo = ImageTk.PhotoImage(bg_img)
background_label = tk.Label(window, image=bg_photo, bg="#0a0a0a")
background_label.place(x=0, y=0, relwidth=1, relheight=1)

# Header Title
title = tk.Label(
    window, 
    text="AUTOMATED RECON TOOL", 
    fg="#00ff66", 
    bg="#0d1117", 
    font=("Helvetica", 20, "bold"),
    bd=2,
    relief="ridge",
    padx=15,
    pady=5
)
title.place(x=310, y=20)

# Target Domain Input Label & Field
domain_label = tk.Label(
    window, 
    text="Target Domain:", 
    fg="#00ff66", 
    bg="#0d1117", 
    font=("Courier", 13, "bold"),
    padx=8,
    pady=3
)
domain_label.place(x=100, y=82)

domain_entry = tk.Entry(
    window, 
    font=("Courier", 13), 
    width=38,
    bg="#161b22",
    fg="#00ff66",
    insertbackground="#00ff66",
    bd=2,
    relief="groove"
)
domain_entry.place(x=270, y=82)

# Output Display Text Area
result_text = scrolledtext.ScrolledText(
    window, 
    wrap=tk.WORD, 
    font=("Courier", 11),
    bg="#0d1117", 
    fg="#00ff66", 
    insertbackground="white",
    bd=3,
    relief="groove"
)
result_text.place(x=100, y=135, width=800, height=370)

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert_bin = s.getpeercert(True)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
            subject = dict(cert.get_subject().get_components())
            issuer = dict(cert.get_issuer().get_components())
            ssl_info = f"""SSL Certificate Information:
    - Common Name: {subject.get(b'CN', b'N/A').decode()}
    - Organization: {subject.get(b'O', b'N/A').decode()}
    - Issuer: {issuer.get(b'O', b'N/A').decode()}
    - Valid From: {cert.get_notBefore().decode('utf-8')}
    - Valid Until: {cert.get_notAfter().decode('utf-8')}\n"""
            return ssl_info
    except Exception as e:
        return f"SSL Info: Failed to retrieve SSL info: {str(e)}\n"

def start_recon():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain.")
        return
    
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"[+] Starting recon for: {domain}\n\n")
    try:
        ip = socket.gethostbyname(domain)
        result_text.insert(tk.END, f"[+] IP Address: {ip}\n")
    except Exception:
        result_text.insert(tk.END, "[-] Could not resolve IP address.\n")
        ip = None

    if ip:
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            data = resp.json()
            city = data.get("city", "N/A")
            region = data.get("region", "N/A")
            country = data.get("country", "N/A")
            result_text.insert(tk.END, f"[+] Location: {city}, {region}, {country}\n")
        except Exception:
            result_text.insert(tk.END, "[-] Could not get geolocation.\n")

    try:
        whois_data = whois.whois(domain)
        result_text.insert(tk.END, f"[+] WHOIS Info:\n{whois_data}\n\n")
    except Exception:
        result_text.insert(tk.END, "[-] WHOIS lookup failed.\n\n")

    record_types = ['A', 'MX', 'NS', 'TXT']
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type, lifetime=5)
            result_text.insert(tk.END, f"[+] {r_type} Records:\n")
            for rdata in answers:
                result_text.insert(tk.END, f"    {rdata.to_text()}\n")
        except Exception:
            result_text.insert(tk.END, f"[-] No {r_type} records found.\n")

    ssl_details = get_ssl_info(domain)
    result_text.insert(tk.END, ssl_details + "\n")

    for file in ['robots.txt', 'sitemap.xml']:
        try:
            url = f"http://{domain}/{file}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                result_text.insert(tk.END, f"[+] Found {file}:\n{r.text[:500]}\n\n")
            else:
                result_text.insert(tk.END, f"[-] {file} not found.\n")
        except Exception:
            result_text.insert(tk.END, f"[-] Error checking {file}.\n")

    admin_paths = ['admin', 'admin/login', 'login', 'admin.php']
    found_panels = []
    for path in admin_paths:
        try:
            url = f"http://{domain}/{path}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                found_panels.append(url)
        except:
            continue

    if found_panels:
        result_text.insert(tk.END, "[+] Possible Admin Panels:\n")
        for url in found_panels:
            result_text.insert(tk.END, f"    {url}\n")
    else:
        result_text.insert(tk.END, "[-] No admin panels found.\n")

    if ip:
        result_text.insert(tk.END, "\n[+] Querying Shodan for target info...\n")
        try:
            shodan_api_key = "O5rTQcTofC66y4q4e7rRRwAM0fQwJRhC"
            api = shodan.Shodan(shodan_api_key)
            shodan_data = api.host(ip)

            result_text.insert(tk.END, f"\n[SHODAN] IP: {shodan_data['ip_str']}\n")
            result_text.insert(tk.END, f"[SHODAN] Organization: {shodan_data.get('org', 'N/A')}\n")
            result_text.insert(tk.END, f"[SHODAN] OS: {shodan_data.get('os', 'N/A')}\n")
            result_text.insert(tk.END, "[SHODAN] Open Ports & Services:\n")
            for item in shodan_data['data']:
                port = item.get('port', 'N/A')
                banner = item.get('data', '')[:100].strip().replace('\n', ' ')
                result_text.insert(tk.END, f"  Port {port} -> {banner}...\n")
        except shodan.APIError as e:
            result_text.insert(tk.END, f"[!] Shodan Error: {str(e)}\n")
        except Exception:
            result_text.insert(tk.END, f"[!] Failed to query Shodan.\n")

    result_text.insert(tk.END, "\n[+] Recon Complete.\n")

def export_to_pdf():
    content = result_text.get("1.0", tk.END).strip()
    if not content:
        messagebox.showerror("No Output", "No recon results to export.")
        return

    safe_content = ''.join(char if ord(char) < 128 else '?' for char in content)

    filepath = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if not filepath:
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Automatic Reconnaissance Report", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", size=11)

    lines = safe_content.split('\n')
    for line in lines:
        while len(line) > 110:
            pdf.multi_cell(0, 8, line[:110])
            line = line[110:]
        pdf.multi_cell(0, 8, line)

    try:
        pdf.output(filepath)
        messagebox.showinfo("Success", f"PDF saved as:\n{filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save PDF:\n{str(e)}")

def clear_output():
    result_text.delete(1.0, tk.END)

# Control Action Buttons
btn_start = tk.Button(
    window, 
    text="Start Recon", 
    command=start_recon,
    bg="#00aa44", 
    fg="white", 
    activebackground="#00e65c",
    activeforeground="white",
    font=("Courier", 11, "bold"),
    bd=2,
    relief="raised"
)
btn_start.place(x=170, y=540, width=170, height=40)

btn_export = tk.Button(
    window, 
    text="Export PDF", 
    command=export_to_pdf, 
    bg="#0077cc", 
    fg="white", 
    activebackground="#0099ff",
    activeforeground="white",
    font=("Courier", 11, "bold"),
    bd=2,
    relief="raised"
)
btn_export.place(x=365, y=540, width=170, height=40)

btn_clear = tk.Button(
    window, 
    text="Clear Output", 
    command=clear_output,
    bg="#cc6600", 
    fg="white", 
    activebackground="#ff8000",
    activeforeground="white",
    font=("Courier", 11, "bold"),
    bd=2,
    relief="raised"
)
btn_clear.place(x=560, y=540, width=170, height=40)

btn_exit = tk.Button(
    window, 
    text="Exit", 
    command=window.destroy,
    bg="#b30000", 
    fg="white", 
    activebackground="#e60000",
    activeforeground="white",
    font=("Courier", 11, "bold"),
    bd=2,
    relief="raised"
)
btn_exit.place(x=755, y=540, width=120, height=40)

window.mainloop()