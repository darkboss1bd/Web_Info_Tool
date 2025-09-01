import tkinter as tk
from tkinter import ttk, messagebox
import requests
import re
import threading
import time
import random

# --- Main Application Class ---
class DarkBoss1BD_Tool:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 darkboss1bd - Web Email Extractor")
        self.root.geometry("700x500")
        self.root.resizable(False, False)
        self.root.configure(bg="#0e0e0e")

        # Icon (optional, comment if not available)
        # root.iconbitmap('hacker.ico')  # Optional: add icon

        self.create_widgets()

    def create_widgets(self):
        # === BANNER ===
        banner_text = """
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █   ▄▄    ▄   ▄█ ▄▄    ▄   ▄█ ▄▄▀█ ▄▄▀█ ▄▄█ ▄▄▀█ ▄▀█ ▄▄█ ▄▄█ ▄▄▀█ ▄▄█ ▄▄▀█ ▄▄▀   █
    █   ▄▄█  █ █  ██ ▄▄█  █ █  ██ ▄▄▀█ ▄▄▀█ ▄▄█ ▄███ █ █▄▄█ █ ▄▄█ ▄▄▀█▄▄▀█ ▄▄▀█ ▄██   █
    █   ▄▄█  █▄█  ██ ▄▄█  █▄█  ██ ▀▀ █ ▀▀ █▄▄▄█ ▀▀ █▄▄▄█▄▄▄█▄▄▄█ ▀▀ █▄▄▄█ ▀▀ █ ▀▀▄   █
    █                                                                        █
    █           █  DARKBOSS1BD - EMAIL EXTRACTOR FROM WEBSITE  █             █
    █                                                                        █
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
        """
        banner = tk.Label(
            self.root,
            text=banner_text,
            font=("Courier", 9),
            fg="#00ff00",
            bg="#0e0e0e",
            justify="left",
            anchor="w"
        )
        banner.pack(pady=10)

        # === URL Input ===
        tk.Label(self.root, text="🌐 Enter Website URL:", fg="cyan", bg="#0e0e0e", font=("Helvetica", 12)).pack(pady=5)
        self.url_entry = ttk.Entry(self.root, width=50, font=("Helvetica", 11))
        self.url_entry.pack(pady=5)
        self.url_entry.insert(0, "https://example.com")

        # === Scan Button ===
        self.scan_btn = ttk.Button(self.root, text="🚀 Start Scan", command=self.start_scan)
        self.scan_btn.pack(pady=10)

        # === Animation Frame ===
        self.anim_canvas = tk.Canvas(self.root, width=680, height=100, bg="black", highlightthickness=0)
        self.anim_canvas.pack(pady=5)
        self.anim_text_id = self.anim_canvas.create_text(
            10, 50,
            text="", font=("Courier", 10), fill="green", anchor="w"
        )
        self.anim_running = False

        # === Results Box ===
        result_frame = tk.Frame(self.root, bg="#111")
        result_frame.pack(padx=20, pady=10, fill="both", expand=True)

        tk.Label(result_frame, text="🔍 Extracted Emails:", fg="yellow", bg="#111", font=("Helvetica", 10)).pack(anchor="w")

        self.result_text = tk.Text(result_frame, wrap="word", height=8, bg="#1e1e1e", fg="#00ff00",
                                   insertbackground="white", font=("Courier", 10))
        self.result_text.pack(fill="both", expand=True, pady=5)
        self.result_text.config(state="disabled")

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.result_text, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

    def animate_hacking(self):
        messages = [
            "[+] Initializing darkboss1bd cyber engine...",
            "[*] Bypassing firewall layers...",
            "[*] Scanning target server...",
            "[*] Fetching HTML source...",
            "[*] Decrypting data streams...",
            "[✓] Target acquired. Searching for emails...",
            "[✓] Extraction complete."
        ]

        x_pos = 10
        for msg in messages:
            if not self.anim_running:
                break
            for char in msg:
                if not self.anim_running:
                    return
                current_text = self.anim_canvas.itemcget(self.anim_text_id, "text")
                new_text = current_text + char
                self.anim_canvas.itemconfig(self.anim_text_id, text=new_text)
                self.anim_canvas.update()
                time.sleep(0.03)
            time.sleep(0.5)
            # Scroll text
            x_pos += 15
            if x_pos > 600:
                x_pos = 10
                self.anim_canvas.delete(self.anim_text_id)
                self.anim_text_id = self.anim_canvas.create_text(
                    10, 50, text="", font=("Courier", 10), fill="green", anchor="w"
                )
            else:
                time.sleep(0.7)
                self.anim_canvas.move(self.anim_text_id, 0, 20)
                self.anim_canvas.update()

    def extract_emails(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        try:
            self.result_text.config(state="normal")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "[~] Fetching data from " + url + "...\n\n")
            self.result_text.config(state="disabled")
            self.result_text.update()

            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            # Find emails using regex
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', response.text)
            emails = list(set(emails))  # Remove duplicates

            self.result_text.config(state="normal")
            self.result_text.delete(1.0, tk.END)
            if emails:
                self.result_text.insert(tk.END, f"🎯 Found {len(emails)} email(s):\n\n")
                for email in emails:
                    self.result_text.insert(tk.END, f"📧  {email}\n")
            else:
                self.result_text.insert(tk.END, "❌ No email addresses found.\n")
            self.result_text.config(state="disabled")

        except requests.exceptions.RequestException as e:
            self.result_text.config(state="normal")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"⚠️  Error: Unable to reach the website.\n{str(e)}")
            self.result_text.config(state="disabled")
        except Exception as e:
            self.result_text.config(state="normal")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"⚠️  Unexpected error: {str(e)}")
            self.result_text.config(state="disabled")

        self.anim_running = False
        self.scan_btn.config(state="normal")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url or url == "https://example.com":
            messagebox.showwarning("Input Error", "Please enter a valid website URL!")
            return

        # Start animation and scan in threads
        self.scan_btn.config(state="disabled")
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state="disabled")
        self.anim_canvas.delete("all")
        self.anim_text_id = self.anim_canvas.create_text(
            10, 50, text="", font=("Courier", 10), fill="green", anchor="w"
        )
        self.anim_running = True

        # Run animation in a thread
        threading.Thread(target=self.animate_hacking, daemon=True).start()

        # Run extraction after delay
        self.root.after(2000, lambda: threading.Thread(target=self.extract_emails, daemon=True).start())

# === Run App ===
if __name__ == "__main__":
    root = tk.Tk()
    app = DarkBoss1BD_Tool(root)
    root.mainloop()
