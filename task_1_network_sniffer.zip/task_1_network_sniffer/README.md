# Task 1: Basic Network Sniffer

## ✅ Objective
To build a Python-based network sniffer that captures and analyzes Ethernet, IP, and TCP traffic.

## 🛠️ Tools Used
- Python
- socket module
- struct module

## 💡 Features
- Captures raw packets
- Extracts Ethernet, IP, and TCP headers
- Displays:
  - Source & Destination MAC Addresses
  - Source & Destination IP Addresses
  - Protocol Type (TCP, UDP, ICMP)
  - Source & Destination Ports (for TCP)

## 🖥️ How to Run

> This script requires **Linux** and **root access** to capture packets.

```bash
sudo python3 network_sniffer.py
