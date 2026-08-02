# IP Blacklist Scanner — Binary Search Threat Checker

A cybersecurity tool that uses **binary search algorithm** to instantly check if an IP address is blacklisted and if open ports are high-risk — designed to work alongside network scanners like NetRecon.

## 🎯 What It Does

```
IP Address + Open Ports → Binary Search → Threat Report
```

- Checks IP against a blacklist database using binary search
- Checks each open port against known risky/exploited ports
- Shows comparison count — proves binary search efficiency
- Works as a post-scan analysis tool after NetRecon

|

Binary search is **100x faster** for large threat databases.

## 🛠️ Tech Stack

- Python 3
- Binary Search Algorithm
- IP to Integer conversion (bitwise)
- Data Structures (sorted lists)

## 🚀 How to Run

```bash
git clone https://github.com/am-cybersec/IP-Blacklist-Scanner
cd IP-Blacklist-Scanner
python blacklist_scanner.py
```

## ⚙️ Usage

```python
checker = ThreatChecker()

# Paste your scanned IP and ports from NetRecon
scanned_ip = "45.33.32.156"
open_ports_found = [22, 80, 3389]

checker.check_scan_data(scanned_ip, open_ports_found)
```

## 📊 Sample Output

```
--- Threat Analysis for 45.33.32.156 ---
IP Check: ⚠️ BLACKLISTED (3 comparisons)
Port Risk Analysis:
  Port 22:   ⚠️ HIGH RISK (4 comparisons)
  Port 80:   ✅ Low risk (4 comparisons)
  Port 3389: ⚠️ HIGH RISK (3 comparisons)
```

## 🔗 Works With NetRecon

This tool is designed to be used **after** running NetRecon port scanner:

```
NetRecon → Open Ports List → IP Blacklist Scanner → Threat Report
```

## 🎓 Project Context

| Detail | Info |
|---|---|
| Course | Data Structures / Cybersecurity |
| Algorithm | Binary Search O(log n) |
| Institution | COMSATS University Islamabad |
