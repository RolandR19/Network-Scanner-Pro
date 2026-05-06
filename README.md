Here is a professional version of your **README.md** written in English, tailored specifically for your GitHub repository **Network-Scanner-Pro**.

# 🚀 Network-Scanner-Pro

A high-performance network auditing and diagnostic tool designed for local environments[cite: 3]. This tool combines the packet manipulation power of `Scapy` with a sophisticated `Rich` terminal interface for clear, professional-grade reporting[cite: 3].

## 📋 Description
**Network-Scanner-Pro** is a robust Python solution engineered to map your entire network[cite: 2]. It provides detailed insights into connected devices, open ports, and real-time connection performance[cite: 2].

## ✨ Features
- 🔍 **ARP Scanning**: Instantly discover all devices on your network, including IP addresses, MAC addresses, and hardware manufacturers[cite: 3].
- 🛡️ **Port Scanner**: Multi-threaded TCP port analysis with service banner grabbing to identify active software[cite: 1, 3].
- 📶 **Wi-Fi Analysis**: Monitor nearby access points, signal quality (RSSI), and security protocols[cite: 3].
- 📈 **Live Statistics**: Real-time traffic monitoring with visual graphs for upload and download throughput[cite: 3].
- 📄 **JSON Reporting**: Automatic generation of comprehensive scan reports in JSON format for later analysis[cite: 3].

## 🛠️ Installation

### Prerequisites
The script requires Python 3.8+[cite: 1]. 

### Dependencies
Install the required packages using `pip`:
```bash
pip install rich scapy netifaces psutil requests manuf
```
*(Alternatively, you can use: `pip install -r requirements.txt`)*[cite: 3].

## 🚀 Usage
Due to low-level network interactions (ARP and Wi-Fi scanning), the script requires **root/administrator** privileges[cite: 1, 3].

```bash
sudo python3 network_scanner.py
```

## 📂 Repository Structure
- `network_scanner.py`: The core application script[cite: 3].
- `requirements.txt`: List of necessary Python libraries[cite: 3].
- `README.md`: Project documentation[cite: 3].


---
*Developed by RolandR19*
