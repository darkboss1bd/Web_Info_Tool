import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import re
import socket
import whois
import dns.resolver
import threading
import time
import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
import nmap
import ssl
import socket
from datetime import datetime

# --- Main Application Class ---
class DarkBoss1BD_UltraTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 darkboss1bd - ULTRA Web Recon Tool")
        self.root.geometry("1000x700")
        self.root.resizable(False, False)

        self.dark_mode = True
        self.results = {}
        self.create_widgets()

    def create_widgets(self):
        # === BANNER ===
        self.banner_text = """
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █   ▄▄    ▄   ▄█ ▄▄    ▄   ▄█ ▄▄▀█ ▄▄▀█ ▄▄█ ▄▄▀█ ▄▀█ ▄▄█ ▄▄█ ▄▄▀█ ▄▄█ ▄▄▀█ ▄▄▀   █
    █   ▄▄█  █ █  ██ ▄▄█  █ █  ██ ▄▄▀█ ▄▄▀█ ▄▄█ ▄███ █ █▄▄█ █ ▄▄█ ▄▄▀█▄▄▀█ ▄▄▀█ ▄██   █
    █   ▄▄█  █▄█  ██ ▄▄█  █▄█  ██ ▀▀ █ ▀▀ █▄▄▄█ ▀▀ █▄▄▄█▄▄▄█▄▄▄█ ▀▀ █▄▄▄█ ▀▀ █ ▀▀▄   █
    █                                                                        █
    █      █  DARKBOSS1BD - ULTRA WEB RECON & CYBER EXPLORER  █              █
    █                                                                        █
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
        """
        self.banner_label = tk.Label(
            self.root,
            text=self.banner_text,
            font=("Courier", 9),
            fg="#00ff00",
            bg="#0e0e0e",
            justify="left",
            anchor="w"
        )
        self.banner_label.pack(pady=5)

        # === URL Input + Theme Toggle ===
        input_frame = tk.Frame(self.root, bg="#0e0e0e")
        input_frame.pack(pady=5)

        tk.Label(input_frame, text="🌐 Enter Website URL:", fg="cyan", bg="#0e0e0e", font=("Helvetica", 12)).pack(side="left")
        self.url_entry = ttk.Entry(input_frame, width=50, font=("Helvetica", 11))
        self.url_entry.pack(side="left", padx=5)
        self.url_entry.insert(0, "https://example.com")

        # Theme Toggle
        self.theme_btn = ttk.Button(input_frame, text="🌓 Light Mode", command=self.toggle_theme)
        self.theme_btn.pack(side="right", padx=10)

        # === Tabs ===
        self.tab_control = ttk.Notebook(self.root)
        self.tab_control.pack(pady=10, padx=20, fill="both", expand=True)

        tabs = [
            ("📧 Emails", "emails"),
            ("🌐 IP Lookup", "ip"),
            ("📜 WHOIS", "whois"),
            ("🔍 Subdomains", "subdomains"),
            ("🔎 Google Dorking", "dorking"),
            ("🚪 Open Ports", "ports"),
            ("🔒 SSL Info", "ssl"),
            ("💾 Save Results", "save")
        ]

        self.tabs_dict = {}
        for title, key in tabs:
            frame = ttk.Frame(self.tab_control)
            self.tab_control.add(frame, text=title)
            self.tabs_dict[key] = frame

        # === Buttons ===
        btn_frame = tk.Frame(self.root, bg="#0e0e0e")
        btn_frame.pack(pady=5)

        self.scan_btn = ttk.Button(btn_frame, text="🚀 Start Full Scan", command=self.start_full_scan)
        self.scan_btn.pack(side="left", padx=5)

        self.save_btn = ttk.Button(btn_frame, text="💾 Save All Results", command=self.save_all_results)
        self.save_btn.pack(side="left", padx=5)

        # === Progress Bar ===
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=960, mode="determinate")
        self.progress.pack(pady=5)

        # === Create Text Widgets for Each Tab ===
        self.create_result_widget(self.tabs_dict["emails"], "Extracted Emails")
        self.create_result_widget(self.tabs_dict["ip"], "IP & Server Info")
        self.create_result_widget(self.tabs_dict["whois"], "WHOIS Information")
        self.create_result_widget(self.tabs_dict["subdomains"], "Subdomains Found")
        self.create_result_widget(self.tabs_dict["dorking"], "Google Dork Queries")
        self.create_result_widget(self.tabs_dict["ports"], "Open Ports (nmap)")
        self.create_result_widget(self.tabs_dict["ssl"], "SSL Certificate Info")

        self.save_text = tk.Text(self.tabs_dict["save"], wrap="word", bg="#1e1e1e", fg="#00ff00", font=("Courier", 10))
        self.save_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.save_text.insert("1.0", "Click 'Save All Results' to export data to TXT or PDF.")
        self.save_text.config(state="disabled")

    def create_result_widget(self, parent, title):
        tk.Label(parent, text=title, bg="#222", fg="yellow", anchor="w").pack(fill="x", padx=5, pady=2)
        text_widget = tk.Text(parent, wrap="word", height=10, bg="#1e1e1e", fg="#00ff00", font=("Courier", 10))
        text_widget.pack(fill="both", expand=True, padx=10, pady=5)
        text_widget.config(state="disabled")
        setattr(self, f"{title.lower().replace(' ', '_').replace('(', '').replace(')', '').replace('-', '_')}_text", text_widget)

    def toggle_theme(self):
        if self.dark_mode:
            self.root.configure(bg="white")
            self.banner_label.config(bg="white", fg="black")
            self.dark_mode = False
            self.theme_btn.config(text="🌑 Dark Mode")
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Label) and widget != self.banner_label:
                    widget.config(bg="white", fg="black")
        else:
            self.root.configure(bg="#0e0e0e")
            self.banner_label.config(bg="#0e0e0e", fg="#00ff00")
            self.dark_mode = True
            self.theme_btn.config(text="🌞 Light Mode")
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Label) and widget != self.banner_label:
                    widget.config(bg="#0e0e0e", fg="white")

    # === SCAN FUNCTIONS ===
    def get_emails(self, domain):
        url = f"http://{domain}" if not domain.startswith("http") else domain
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(url, headers=headers, timeout=10)
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', response.text)
            self.results['emails'] = list(set(emails))
        except:
            self.results['emails'] = []

    def get_ip(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            self.results['ip'] = ip
        except:
            self.results['ip'] = "Not found"

    def get_whois(self, domain):
        try:
            w = whois.whois(domain)
            self.results['whois'] = {
                'registrar': w.registrar or 'N/A',
                'creation_date': w.creation_date or 'N/A',
                'expiration_date': w.expiration_date or 'N/A',
                'name': w.name or 'N/A',
                'org': w.org or 'N/A',
                'country': w.country or 'N/A'
            }
        except:
            self.results['whois'] = {k: 'Error/Not Available' for k in ['registrar', 'creation_date', 'expiration_date', 'name', 'org', 'country']}

    def get_subdomains(self, domain):
        common_subs = ["www", "mail", "ftp", "blog", "shop", "api", "dev", "admin", "panel", "webmail", "cpanel", "smtp"]
        found = []
        for sub in common_subs:
            try:
                test_domain = f"{sub}.{domain}"
                socket.gethostbyname(test_domain)
                found.append(test_domain)
            except:
                continue
        self.results['subdomains'] = found

    def get_google_dorks(self, domain):
        dorks = [
            f'site:{domain}',
            f'site:{domain} intitle:"admin"',
            f'site:{domain} filetype:pdf',
            f'site:{domain} inurl:login',
            f'site:{domain} "email" "contact"',
            f'site:{domain} ext:php | ext:asp | ext:aspx',
            f'"{domain}" "password"',
        ]
        self.results['dorks'] = dorks

    def scan_ports(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            nm = nmap.PortScanner()
            nm.scan(ip, '21,22,80,443,8080')
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        open_ports.append(f"{port}/tcp - {state}")
            self.results['ports'] = open_ports
        except:
            self.results['ports'] = ["nmap not available or error"]

    def get_ssl_info(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    expires = cert['notAfter']

                    self.results['ssl'] = {
                        'subject': subject.get('commonName', 'N/A'),
                        'issuer': issuer.get('commonName', 'N/A'),
                        'expires': expires,
                        'valid': 'Yes'
                    }
        except Exception as e:
            self.results['ssl'] = {
                'subject': 'Error',
                'issuer': 'Error',
                'expires': 'Error',
                'valid': str(e)
            }

    # === MAIN SCAN ===
    def start_full_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL!")
            return

        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        self.clear_all_results()
        self.anim_running = True
        self.scan_btn.config(state="disabled")

        def run_scan():
            tasks = [
                (self.get_emails, domain),
                (self.get_ip, domain),
                (self.get_whois, domain),
                (self.get_subdomains, domain),
                (self.get_google_dorks, domain),
                (self.scan_ports, domain),
                (self.get_ssl_info, domain),
            ]
            for i, (func, arg) in enumerate(tasks):
                self.progress["value"] = (i / len(tasks)) * 100
                self.root.update_idletasks()
                func(arg)
                time.sleep(0.5)

            self.display_emails()
            self.display_ip()
            self.display_whois()
            self.display_subdomains()
            self.display_dorks()
            self.display_ports()
            self.display_ssl()
            self.progress["value"] = 100

            self.scan_btn.config(state="normal")
            messagebox.showinfo("Scan Complete", "✅ All scans completed!")

        threading.Thread(target=run_scan, daemon=True).start()

    def clear_all_results(self):
        for key in self.tabs_dict:
            if key == "save":
                continue
            for widget in self.tabs_dict[key].winfo_children():
                if isinstance(widget, tk.Text):
                    widget.config(state="normal")
                    widget.delete(1.0, tk.END)
                    widget.config(state="disabled")

    # === DISPLAY FUNCTIONS ===
    def display_emails(self):
        w = self.extracted_emails_text
        w.config(state="normal")
        for e in self.results.get('emails', []):
            w.insert(tk.END, f"📧 {e}\n")
        if not self.results.get('emails'):
            w.insert(tk.END, "❌ None found.\n")
        w.config(state="disabled")

    def display_ip(self):
        w = self.ip___server_info_text
        w.config(state="normal")
        w.insert(tk.END, f"🌐 IP: {self.results.get('ip')}\n")
        w.config(state="disabled")

    def display_whois(self):
        w = self.whois_information_text
        w.config(state="normal")
        for k, v in self.results.get('whois', {}).items():
            w.insert(tk.END, f"{k.title()}: {v}\n")
        w.config(state="disabled")

    def display_subdomains(self):
        w = self.subdomains_found_text
        w.config(state="normal")
        for s in self.results.get('subdomains', []):
            w.insert(tk.END, f"🔗 {s}\n")
        if not self.results.get('subdomains'):
            w.insert(tk.END, "🔍 None found.\n")
        w.config(state="disabled")

    def display_dorks(self):
        w = self.google_dork_queries_text
        w.config(state="normal")
        for d in self.results.get('dorks', []):
            w.insert(tk.END, f"🔎 {d}\n")
        w.config(state="disabled")

    def display_ports(self):
        w = self.open_ports_nmap_text
        w.config(state="normal")
        for p in self.results.get('ports', []):
            w.insert(tk.END, f"🚪 {p}\n")
        w.config(state="disabled")

    def display_ssl(self):
        w = self.ssl_certificate_info_text
        w.config(state="normal")
        ssl_data = self.results.get('ssl', {})
        for k, v in ssl_data.items():
            w.insert(tk.END, f"{k.title()}: {v}\n")
        w.config(state="disabled")

    # === SAVE RESULTS ===
    def save_all_results(self):
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to save!")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf")]
        )
        if not save_path:
            return

        try:
            if save_path.endswith(".pdf"):
                self.save_as_pdf(save_path)
            else:
                self.save_as_txt(save_path)
            messagebox.showinfo("Saved", f"✅ Results saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"❌ Failed to save: {str(e)}")

    def save_as_txt(self, path):
        with open(path, "w") as f:
            f.write("=== darkboss1bd - ULTRA Web Recon Report ===\n\n")
            f.write(f"Target: {self.url_entry.get()}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("📧 Emails:\n")
            f.write("\n".join(self.results.get('emails', ['None'])) + "\n\n")

            f.write(f"🌐 IP: {self.results.get('ip')}\n\n")

            f.write("📜 WHOIS:\n")
            for k, v in self.results.get('whois', {}).items():
                f.write(f"{k.title()}: {v}\n")
            f.write("\n")

            f.write("🔍 Subdomains:\n")
            f.write("\n".join(self.results.get('subdomains', ['None'])) + "\n\n")

            f.write("🔎 Google Dorks:\n")
            f.write("\n".join(self.results.get('dorks', [])) + "\n\n")

            f.write("🚪 Open Ports:\n")
            f.write("\n".join(self.results.get('ports', ['None'])) + "\n\n")

            f.write("🔒 SSL Info:\n")
            for k, v in self.results.get('ssl', {}).items():
                f.write(f"{k.title()}: {v}\n")
            f.write("\n")

    def save_as_pdf(self, path):
        c = pdf_canvas.Canvas(path, pagesize=A4)
        width, height = A4
        y = height - 50

        c.setFont("Helvetica-Bold", 16)
        c.setFillColorRGB(0, 1, 0)
        c.drawString(50, y, "darkboss1bd - ULTRA Web Recon Report")
        y -= 40

        c.setFont("Helvetica", 12)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(50, y, f"Target: {self.url_entry.get()}")
        y -= 20
        c.drawString(50, y, f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 40

        sections = [
            ("📧 Emails", self.results.get('emails', ['None'])),
            ("🌐 IP", [self.results.get('ip', 'N/A')]),
            ("📜 WHOIS", [f"{k}: {v}" for k, v in self.results.get('whois', {}).items()]),
            ("🔍 Subdomains", self.results.get('subdomains', ['None'])),
            ("🔎 Google Dorks", self.results.get('dorks', [])),
            ("🚪 Open Ports", self.results.get('ports', ['None'])),
            ("🔒 SSL Info", [f"{k}: {v}" for k, v in self.results.get('ssl', {}).items()]),
        ]

        for title, items in sections:
            if y < 100:
                c.showPage()
                y = height - 50
            c.setFont("Helvetica-Bold", 14)
            c.setFillColorRGB(0.2, 0.4, 0.8)
            c.drawString(50, y, title)
            y -= 25
            c.setFont("Helvetica", 11)
            c.setFillColorRGB(0, 0, 0)
            for item in items:
                if y < 100:
                    c.showPage()
                    y = height - 50
                c.drawString(70, y, f"• {item}")
                y -= 20
            y -= 20

        c.save()

# === Run App ===
if __name__ == "__main__":
    root = tk.Tk()
    app = DarkBoss1BD_UltraTool(root)
    root.mainloop()
