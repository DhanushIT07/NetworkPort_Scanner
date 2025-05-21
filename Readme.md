# 🔍 Python Port Scanner

A beginner-friendly network scanner built using Python and the `nmap` module. This tool allows users to scan open ports on a specified IP address or domain using different scan types like SYN, UDP, and Comprehensive scans.

## 🚀 Features

- Accepts user input for target IP or domain
- Supports multiple scan types:
  - SYN scan (`-sS`)
  - UDP scan (`-sU`)
  - Comprehensive scan (`-sS -sV -O -A`)
- Uses `nmap` under the hood for accurate and detailed results
- CLI-based, interactive interface
- Displays scan results in a readable format
- Option to save the scan report

## 📦 Requirements

- Python 3.6+
- `python-nmap` module
- Nmap must be installed on your system

## 💻 Installation

```bash
pip install python-nmap

## The Result is saved a File
