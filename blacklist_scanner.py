import tkinter as tk
from tkinter import ttk, scrolledtext
import time

class ThreatChecker:
    def __init__(self):
        self.risky_ports = sorted([21, 22, 23, 25, 135, 139, 445, 1433,
                                   3306, 3389, 5900, 6379, 8080, 9200])
        self.blacklisted_ips = sorted([
            "1.2.3.4", "45.33.32.156", "89.248.165.15",
            "185.220.101.1", "192.42.116.16"
        ])

    def binary_search_port(self, port):
        low, high = 0, len(self.risky_ports) - 1
        comparisons = 0
        while low <= high:
            comparisons += 1
            mid = (low + high) // 2
            if self.risky_ports[mid] == port:
                return True, comparisons
            elif self.risky_ports[mid] < port:
                low = mid + 1
            else:
                high = mid - 1
        return False, comparisons

    def ip_to_int(self, ip):
        parts = ip.split('.')
        return int(''.join(f"{int(x):08b}" for x in parts), 2)

    def binary_search_ip(self, target_ip):
        ip_ints = [self.ip_to_int(ip) for ip in self.blacklisted_ips]
        target = self.ip_to_int(target_ip)
        low, high = 0, len(ip_ints) - 1
        comparisons = 0
        while low <= high:
            comparisons += 1
            mid = (low + high) // 2
            if ip_ints[mid] == target:
                return True, comparisons
            elif ip_ints[mid] < target:
                low = mid + 1
            else:
                high = mid - 1
        return False, comparisons

    def check_scan_data(self, ip, open_ports):
        results = []
        ip_flagged, ip_comp = self.binary_search_ip(ip)
        results.append(("ip", ip, ip_flagged, ip_comp))
        for port in open_ports:
            risky, comp = self.binary_search_port(port)
            results.append(("port", port, risky, comp))
        return results


class ThreatCheckerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Blacklist & Port Threat Scanner")
        self.root.configure(bg="#0d1117")
        self.root.geometry("750x600")
        self.checker = ThreatChecker()
        self.build_ui()

    def build_ui(self):
        # Title
        tk.Label(self.root, text="🔐 IP Blacklist & Port Threat Scanner",
                 bg="#0d1117", fg="#58a6ff",
                 font=("Courier New", 14, "bold")).pack(pady=(18, 4))
        tk.Label(self.root, text="Binary Search Threat Detection Engine",
                 bg="#0d1117", fg="#8b949e",
                 font=("Courier New", 9)).pack(pady=(0, 14))

        # Input frame
        frame = tk.Frame(self.root, bg="#161b22",
                         highlightbackground="#30363d",
                         highlightthickness=1)
        frame.pack(padx=20, fill="x", pady=(0, 10))

        tk.Label(frame, text="Target IP Address:",
                 bg="#161b22", fg="#8b949e",
                 font=("Courier New", 9)).grid(row=0, column=0,
                 sticky="w", padx=14, pady=(12, 4))
        self.ip_entry = tk.Entry(frame, bg="#0d1117", fg="#c9d1d9",
                                  insertbackground="#58a6ff",
                                  font=("Courier New", 11),
                                  highlightbackground="#30363d",
                                  highlightthickness=1, relief="flat",
                                  width=30)
        self.ip_entry.insert(0, "45.33.32.156")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=(12, 4), sticky="w")

        tk.Label(frame, text="Open Ports (comma separated):",
                 bg="#161b22", fg="#8b949e",
                 font=("Courier New", 9)).grid(row=1, column=0,
                 sticky="w", padx=14, pady=(4, 12))
        self.port_entry = tk.Entry(frame, bg="#0d1117", fg="#c9d1d9",
                                    insertbackground="#58a6ff",
                                    font=("Courier New", 11),
                                    highlightbackground="#30363d",
                                    highlightthickness=1, relief="flat",
                                    width=30)
        self.port_entry.insert(0, "22, 80, 3389, 8080")
        self.port_entry.grid(row=1, column=1, padx=10, pady=(4, 12), sticky="w")

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#0d1117")
        btn_frame.pack(pady=(0, 10))

        tk.Button(btn_frame, text="  Run Threat Scan  ",
                  bg="#1f6feb", fg="white",
                  font=("Courier New", 10, "bold"),
                  relief="flat", cursor="hand2",
                  command=self.run_scan).pack(side="left", padx=6)

        tk.Button(btn_frame, text="  Clear  ",
                  bg="#21262d", fg="#c9d1d9",
                  font=("Courier New", 10),
                  relief="flat", cursor="hand2",
                  command=self.clear).pack(side="left", padx=6)

        tk.Button(btn_frame, text="  Try Blacklisted IP  ",
                  bg="#21262d", fg="#f85149",
                  font=("Courier New", 10),
                  relief="flat", cursor="hand2",
                  command=lambda: self.set_example("45.33.32.156", "22, 3389, 445")).pack(side="left", padx=6)

        tk.Button(btn_frame, text="  Try Clean IP  ",
                  bg="#21262d", fg="#3fb950",
                  font=("Courier New", 10),
                  relief="flat", cursor="hand2",
                  command=lambda: self.set_example("127.0.0.1", "80, 443, 8080")).pack(side="left", padx=6)

        # Terminal output
        self.terminal = scrolledtext.ScrolledText(
            self.root, bg="#0d1117", fg="#c9d1d9",
            font=("Courier New", 10),
            insertbackground="#58a6ff",
            highlightbackground="#30363d",
            highlightthickness=1,
            relief="flat", height=18,
            wrap="word"
        )
        self.terminal.pack(padx=20, pady=(0, 16), fill="both", expand=True)

        self.terminal.tag_config("green",  foreground="#3fb950")
        self.terminal.tag_config("red",    foreground="#f85149")
        self.terminal.tag_config("yellow", foreground="#d29922")
        self.terminal.tag_config("blue",   foreground="#58a6ff")
        self.terminal.tag_config("muted",  foreground="#8b949e")

        self.log("[*] Scanner ready. Enter an IP and ports to begin.\n", "blue")

    def set_example(self, ip, ports):
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, ports)

    def clear(self):
        self.terminal.config(state="normal")
        self.terminal.delete("1.0", tk.END)
        self.log("[*] Cleared. Ready for new scan.\n", "blue")

    def log(self, text, tag=None):
        self.terminal.config(state="normal")
        if tag:
            self.terminal.insert(tk.END, text, tag)
        else:
            self.terminal.insert(tk.END, text)
        self.terminal.see(tk.END)
        self.terminal.config(state="disabled")

    def run_scan(self):
        ip = self.ip_entry.get().strip()
        ports_raw = self.port_entry.get().strip()

        if not ip:
            self.log("[!] Please enter an IP address.\n", "red")
            return

        try:
            open_ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
        except ValueError:
            self.log("[!] Invalid port format. Use comma-separated numbers.\n", "red")
            return

        self.log(f"\n{'='*50}\n", "muted")
        self.log(f"[*] Starting threat scan for: {ip}\n", "blue")
        self.log(f"[*] Ports to check: {open_ports}\n", "muted")
        self.log(f"{'='*50}\n", "muted")

        results = self.checker.check_scan_data(ip, open_ports)
        threats = 0

        for item in results:
            if item[0] == "ip":
                _, ip_addr, flagged, comps = item
                if flagged:
                    self.log(f"\n⚠️  IP {ip_addr}: BLACKLISTED", "red")
                    threats += 1
                else:
                    self.log(f"\n✅  IP {ip_addr}: Clean", "green")
                self.log(f"  ({comps} binary search comparisons)\n", "muted")

            elif item[0] == "port":
                _, port, risky, comps = item
                if risky:
                    self.log(f"⚠️  Port {port}: HIGH RISK", "red")
                    threats += 1
                else:
                    self.log(f"✅  Port {port}: Low risk", "green")
                self.log(f"  ({comps} binary search comparisons)\n", "muted")

        self.log(f"\n{'='*50}\n", "muted")
        if threats > 0:
            self.log(f"[!] SCAN COMPLETE — {threats} threat(s) detected!\n", "red")
        else:
            self.log("[✓] SCAN COMPLETE — No threats found.\n", "green")
        self.log(f"{'='*50}\n\n", "muted")


if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatCheckerUI(root)
    root.mainloop()