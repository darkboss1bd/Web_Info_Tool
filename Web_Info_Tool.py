import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import whois
import re
import socket
import os
from datetime import datetime
from fpdf import FPDF

# --- Hacker Animation Text ---
hacker_lines = [
    "█▓▒░░ CONNEXION SECURITE ACTIVEE ░░▒▓█",
    "ACCES AU SYSTEME EN COURS...",
    "DECRYPTAGE DES DONNEES...",
    "BYPASSING FIREWALL...",
    "ROOT ACCESS OBTENU...",
    "SCANNING TARGET...",
    "EXPLOITATION DES VULNERABILITES...",
    "DATA EXTRACTION IN PROGRESS...",
    "█████████ HACKED █████████",
    "darkboss1bd - POWER TO THE PENTEST",
    "█▓▒░░░░░░░░░░░░░░░░░░░░░░░░░▒▓█"
]

# --- Main Application ---
class WebInfoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 darkboss1bd - Web Info Tool")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#0e0e0e")

        # --- Banner ---
        banner = tk.Label(
            root,
            text="🔥 darkboss1bd 🔥",
            font=("Courier", 18, "bold"),
            fg="#00ff00",
            bg="#0e0e0e"
        )
        banner.pack(pady=10)

        # --- Hacker Animation Canvas ---
        self.canvas = tk.Canvas(root, width=860, height=80, bg="black", highlightthickness=0)
        self.canvas.pack(pady=5)
        self.text_id = self.canvas.create_text(860, 40, text="", font=("Courier", 10), fill="green", anchor="w")
        self.animate_index = 0
        self.char_index = 0
        self.current_line = ""
        self.animate()

        # --- Input Frame ---
        input_frame = tk.Frame(root, bg="#1a1a1a")
        input_frame.pack(pady=10, padx=20, fill="x")

        tk.Label(input_frame, text="🌐 Website URL (e.g., example.com):", fg="white", bg="#1a1a1a").pack(side="left", padx=5)
        self.url_entry = tk.Entry(input_frame, width=40, font=("Arial", 12), bg="#333", fg="#00ff00", insertbackground="green")
        self.url_entry.pack(side="left", padx=5)

        # --- Buttons Frame ---
        btn_frame = tk.Frame(root, bg="#0e0e0e")
        btn_frame.pack(pady=10)

        self.scan_btn = tk.Button(btn_frame, text="🔍 Scan", command=self.scan_website, bg="#006400", fg="white", width=12, font=("Arial", 10, "bold"))
        self.scan_btn.grid(row=0, column=0, padx=5)

        self.save_btn = tk.Button(btn_frame, text="💾 Save Result", command=self.save_result, bg="#000080", fg="white", width=12, font=("Arial", 10, "bold"))
        self.save_btn.grid(row=0, column=1, padx=5)

        self.clear_btn = tk.Button(btn_frame, text="🗑️ Clear", command=self.clear_result, bg="#8B0000", fg="white", width=12, font=("Arial", 10, "bold"))
        self.clear_btn.grid(row=0, column=2, padx=5)

        # --- Result Text Area ---
        result_frame = tk.Frame(root)
        result_frame.pack(pady=10, padx=20, fill="both", expand=True)

        self.result_text = tk.Text(result_frame, wrap="word", height=25, bg="#111", fg="#00ff00", font=("Courier", 10), insertbackground="green")
        self.scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=self.scrollbar.set)

        self.result_text.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.results = ""

    def animate(self):
        if self.animate_index < len(hacker_lines):
            line = hacker_lines[self.animate_index]
            if self.char_index < len(line):
                self.current_line += line[self.char_index]
                self.char_index += 1
                self.canvas.itemconfig(self.text_id, text=self.current_line)
            else:
                self.char_index = 0
                self.animate_index += 1
                self.current_line = ""
        else:
            self.animate_index = 0
            self.current_line = ""
            self.char_index = 0

        self.canvas.move(self.text_id, -2, 0)
        coords = self.canvas.coords(self.text_id)
        if coords[0] < -800:
            self.canvas.move(self.text_id, 1800, 0)
            if self.animate_index < len(hacker_lines):
                self.current_line = hacker_lines[self.animate_index][:self.char_index+1]

        self.root.after(100, self.animate)

    def scan_website(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a website URL!")
            return

        # Normalize URL
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        if not domain:
            messagebox.showerror("Error", "Invalid URL!")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"🔍 Scanning {domain} ...\n\n")
        self.results = f"=== Scan Report for {domain} ===\nGenerated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        try:
            ip = socket.gethostbyname(domain)
            self.results += f"🌐 Domain: {domain}\nIP Address: {ip}\n\n"

            # Email Extraction
            emails = self.extract_emails(domain)
            self.results += f"📧 Emails Found: {', '.join(emails) if emails else 'None'}\n\n"

            # WHOIS
            whois_info = whois.whois(domain)
            self.results += "📜 WHOIS Information:\n"
            self.results += f"  Registrar: {whois_info.registrar or 'N/A'}\n"
            self.results += f"  Creation Date: {whois_info.creation_date}\n"
            self.results += f"  Expiration Date: {whois_info.expiration_date}\n"
            self.results += f"  Name Servers: {', '.join(whois_info.name_servers) if whois_info.name_servers else 'N/A'}\n\n"

            # Subdomain Check (Basic)
            subdomains = ["www", "mail", "ftp", "blog", "admin", "cpanel", "webmail", "smtp"]
            self.results += "🔍 Subdomain Check:\n"
            for sub in subdomains:
                test_domain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(test_domain)
                    self.results += f"  ✅ {test_domain}\n"
                except socket.gaierror:
                    self.results += f"  ❌ {test_domain}\n"
            self.results += "\n"

            # Final Output
            self.result_text.insert(tk.END, self.results)
            messagebox.showinfo("Success", "Scan completed successfully!")

        except Exception as e:
            error_msg = f"❌ Error: {str(e)}"
            self.result_text.insert(tk.END, error_msg)
            self.results += error_msg

    def extract_emails(self, domain):
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
            return list(set(emails))
        except:
            return []

    def save_result(self):
        if not self.results:
            messagebox.showwarning("No Data", "Nothing to save! Please scan first.")
            return

        file_type = messagebox.askquestion("Save As", "Save as PDF? (Yes for PDF, No for TXT)")

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt" if file_type == 'no' else ".pdf",
            filetypes=[("PDF files", "*.pdf"), ("Text files", "*.txt")]
        )

        if not file_path:
            return

        try:
            if file_type == 'yes':  # PDF
                pdf = FPDF()
                pdf.add_page()
                pdf.set_auto_page_break(auto=True, margin=15)
                pdf.set_font("Courier", size=10)
                for line in self.results.split('\n'):
                    pdf.cell(0, 5, txt=line, ln=True)
                pdf.output(file_path)
            else:  # TXT
                with open(file_path, 'w') as f:
                    f.write(self.results)
            messagebox.showinfo("Saved", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save: {str(e)}")

    def clear_result(self):
        self.result_text.delete(1.0, tk.END)
        self.results = ""
        self.url_entry.delete(0, tk.END)


# --- Run App ---
if __name__ == "__main__":
    root = tk.Tk()
    app = WebInfoTool(root)
    root.mainloop()
