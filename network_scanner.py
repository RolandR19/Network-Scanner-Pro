#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          NETWORK SCANNER PRO — Analyse complète des réseaux      ║
║          Auteur: Généré par Claude | Requires: Python 3.8+       ║
╚══════════════════════════════════════════════════════════════════╝

INSTALLATION DES DÉPENDANCES:
    pip install rich scapy netifaces psutil requests manuf

LANCER LE SCRIPT:
    sudo python3 network_scanner.py

NOTE: Certaines fonctions nécessitent les droits root/admin (sudo)
      pour accéder aux interfaces réseau bas niveau.
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess
import json
import re
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Vérification des dépendances ────────────────────────────────────────────
MISSING = []
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
    from rich.align import Align
    from rich.style import Style
    from rich.markup import escape
    import rich.traceback
    rich.traceback.install()
except ImportError:
    MISSING.append("rich")

try:
    import psutil
except ImportError:
    MISSING.append("psutil")

try:
    import netifaces
except ImportError:
    MISSING.append("netifaces")

try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    MISSING.append("scapy")
    SCAPY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    MISSING.append("requests")
    REQUESTS_AVAILABLE = False

try:
    from manuf import manuf
    MANUF_AVAILABLE = True
except ImportError:
    MANUF_AVAILABLE = False

if MISSING:
    print(f"\n[ERREUR] Modules manquants: {', '.join(MISSING)}")
    print(f"Installez-les avec:\n  pip install {' '.join(MISSING)}\n")
    sys.exit(1)

console = Console()

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES & CONFIG
# ══════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP-Submit",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS5",
    1194: "OpenVPN", 1433: "MSSQL", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 2375: "Docker", 2376: "Docker-TLS", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 6881: "BitTorrent", 7070: "RealAudio",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8883: "MQTT-TLS", 9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster", 27017: "MongoDB", 32400: "Plex",
}

BANNER = """
[bold cyan]
 ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan][bold yellow]
  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold yellow]
[dim cyan]         ◆ Analyse réseau complète & détaillée ◆[/dim cyan]
"""

# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — INTERFACES RÉSEAU LOCALES
# ══════════════════════════════════════════════════════════════════════════════

def get_local_interfaces():
    """Récupère toutes les interfaces réseau avec leurs détails complets."""
    interfaces = []

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(iface_name)
        io = psutil.net_io_counters(pernic=True).get(iface_name)

        iface = {
            "name": iface_name,
            "is_up": stats.isup if stats else False,
            "speed": stats.speed if stats else 0,
            "mtu": stats.mtu if stats else 0,
            "duplex": str(stats.duplex).replace("NicDuplex.", "") if stats else "N/A",
            "ipv4": [],
            "ipv6": [],
            "mac": None,
            "bytes_sent": io.bytes_sent if io else 0,
            "bytes_recv": io.bytes_recv if io else 0,
            "packets_sent": io.packets_sent if io else 0,
            "packets_recv": io.packets_recv if io else 0,
            "errors_in": io.errin if io else 0,
            "errors_out": io.errout if io else 0,
            "drops_in": io.dropin if io else 0,
            "drops_out": io.dropout if io else 0,
        }

        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                iface["ipv4"].append({
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast,
                    "network": str(ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )) if addr.netmask else None
                })
            elif addr.family == socket.AF_INET6:
                iface["ipv6"].append({
                    "address": addr.address.split("%")[0],
                    "netmask": addr.netmask,
                    "scope": addr.address.split("%")[1] if "%" in addr.address else "global"
                })
            elif addr.family == psutil.AF_LINK:
                iface["mac"] = addr.address

        interfaces.append(iface)

    return interfaces


def display_interfaces(interfaces):
    """Affiche les interfaces réseau dans un tableau riche."""
    console.print(Rule("[bold cyan]◆ INTERFACES RÉSEAU LOCALES[/bold cyan]", style="cyan"))

    for iface in interfaces:
        status_icon = "🟢" if iface["is_up"] else "🔴"
        status_text = "[green]ACTIF[/green]" if iface["is_up"] else "[red]INACTIF[/red]"

        t = Table(
            title=f"{status_icon} {iface['name']}  {status_text}",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold cyan",
            title_style="bold white",
        )
        t.add_column("Propriété", style="bold yellow", min_width=22)
        t.add_column("Valeur", style="white")

        t.add_row("Adresse MAC", iface["mac"] or "[dim]N/A[/dim]")
        t.add_row("Vitesse", f"{iface['speed']} Mbps" if iface["speed"] > 0 else "[dim]N/A[/dim]")
        t.add_row("MTU", str(iface["mtu"]))
        t.add_row("Duplex", iface["duplex"])

        for ipv4 in iface["ipv4"]:
            t.add_row("IPv4", ipv4["address"])
            t.add_row("  └ Masque", ipv4["netmask"] or "[dim]N/A[/dim]")
            t.add_row("  └ Broadcast", ipv4["broadcast"] or "[dim]N/A[/dim]")
            t.add_row("  └ Réseau CIDR", ipv4["network"] or "[dim]N/A[/dim]")

        for ipv6 in iface["ipv6"]:
            t.add_row("IPv6", ipv6["address"])
            t.add_row("  └ Scope", ipv6["scope"])

        t.add_row("─── Trafic ───", "")
        t.add_row("Octets envoyés", f"{iface['bytes_sent']:,} B ({iface['bytes_sent']//1024//1024} MB)")
        t.add_row("Octets reçus",   f"{iface['bytes_recv']:,} B ({iface['bytes_recv']//1024//1024} MB)")
        t.add_row("Paquets envoyés", f"{iface['packets_sent']:,}")
        t.add_row("Paquets reçus",  f"{iface['packets_recv']:,}")
        t.add_row("Erreurs (in/out)", f"{iface['errors_in']} / {iface['errors_out']}")
        t.add_row("Pertes (in/out)", f"{iface['drops_in']} / {iface['drops_out']}")

        console.print(t)
        console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — WIFI (via iwlist / airport / netsh)
# ══════════════════════════════════════════════════════════════════════════════

def scan_wifi_linux():
    """Scan WiFi sous Linux via iwlist ou nmcli."""
    networks = []

    # Essaye nmcli d'abord (plus fiable)
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f",
             "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY",
             "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 9:
                    net = {
                        "ssid":     parts[0] or "[caché]",
                        "bssid":    ":".join(parts[1:7]) if len(parts) > 7 else parts[1],
                        "mode":     parts[7] if len(parts) > 7 else "N/A",
                        "channel":  parts[8] if len(parts) > 8 else "N/A",
                        "freq":     parts[9] if len(parts) > 9 else "N/A",
                        "rate":     parts[10] if len(parts) > 10 else "N/A",
                        "signal":   parts[11] if len(parts) > 11 else "N/A",
                        "bars":     parts[12] if len(parts) > 12 else "",
                        "security": parts[13] if len(parts) > 13 else "N/A",
                    }
                    networks.append(net)
            return networks
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: iwlist
    try:
        ifaces = [i for i in psutil.net_if_stats() if "wlan" in i or "wifi" in i.lower() or "wlp" in i]
        if not ifaces:
            return []
        iface = ifaces[0]
        result = subprocess.run(
            ["iwlist", iface, "scan"],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode == 0:
            cells = result.stdout.split("Cell ")
            for cell in cells[1:]:
                net = {}
                m = re.search(r'ESSID:"([^"]*)"', cell)
                net["ssid"] = m.group(1) if m else "[caché]"
                m = re.search(r'Address: ([\w:]+)', cell)
                net["bssid"] = m.group(1) if m else "N/A"
                m = re.search(r'Channel:(\d+)', cell)
                net["channel"] = m.group(1) if m else "N/A"
                m = re.search(r'Frequency:([\d.]+ \w+)', cell)
                net["freq"] = m.group(1) if m else "N/A"
                m = re.search(r'Signal level=(-?\d+)', cell)
                net["signal"] = m.group(1) + " dBm" if m else "N/A"
                m = re.search(r'Bit Rates?:([\d.]+ \w+/s)', cell)
                net["rate"] = m.group(1) if m else "N/A"
                enc = "Open"
                if "WPA2" in cell: enc = "WPA2"
                elif "WPA" in cell: enc = "WPA"
                elif "WEP" in cell: enc = "WEP"
                net["security"] = enc
                net["mode"] = "N/A"
                net["bars"] = ""
                networks.append(net)
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass

    return networks


def scan_wifi_macos():
    """Scan WiFi sous macOS via airport."""
    networks = []
    try:
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        result = subprocess.run([airport, "-s"], capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    networks.append({
                        "ssid": parts[0],
                        "bssid": parts[1],
                        "signal": parts[2] + " dBm",
                        "channel": parts[3],
                        "security": parts[6] if len(parts) > 6 else "N/A",
                        "freq": "N/A", "rate": "N/A",
                        "mode": "N/A", "bars": "",
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return networks


def scan_wifi_windows():
    """Scan WiFi sous Windows via netsh."""
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, timeout=20, encoding="cp850"
        )
        if result.returncode == 0:
            blocks = result.stdout.split("SSID ")
            for block in blocks[1:]:
                net = {}
                m = re.search(r'^\d+ : (.+)', block)
                net["ssid"] = m.group(1).strip() if m else "[caché]"
                m = re.search(r'Type de réseau\s+:\s+(.+)', block)
                net["mode"] = m.group(1).strip() if m else "N/A"
                m = re.search(r'Authentification\s+:\s+(.+)', block)
                net["security"] = m.group(1).strip() if m else "N/A"
                m = re.search(r'BSSID \d+\s+:\s+([\w:]+)', block)
                net["bssid"] = m.group(1).strip() if m else "N/A"
                m = re.search(r'Signal\s+:\s+(\d+)%', block)
                net["signal"] = m.group(1) + "%" if m else "N/A"
                m = re.search(r'Canal\s+:\s+(\d+)', block)
                net["channel"] = m.group(1) if m else "N/A"
                net["freq"] = "N/A"
                net["rate"] = "N/A"
                net["bars"] = ""
                networks.append(net)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return networks


def scan_wifi():
    """Détecte le système et lance le bon scanner WiFi."""
    if sys.platform.startswith("linux"):
        return scan_wifi_linux()
    elif sys.platform == "darwin":
        return scan_wifi_macos()
    elif sys.platform == "win32":
        return scan_wifi_windows()
    return []


def signal_bar(signal_str):
    """Convertit un signal en barre visuelle."""
    try:
        val = int(re.search(r'-?(\d+)', signal_str).group())
        if signal_str.endswith("%"):
            pct = val
        else:
            # dBm → pourcentage approximatif
            pct = max(0, min(100, 2 * (val + 100)))
        bars = int(pct / 20)
        full = "█" * bars
        empty = "░" * (5 - bars)
        color = "green" if pct >= 60 else "yellow" if pct >= 30 else "red"
        return f"[{color}]{full}{empty}[/{color}] {pct}%"
    except Exception:
        return signal_str


def display_wifi(networks):
    """Affiche les réseaux WiFi détectés."""
    console.print(Rule("[bold cyan]◆ RÉSEAUX WIFI DÉTECTÉS[/bold cyan]", style="cyan"))

    if not networks:
        console.print(Panel(
            "[yellow]⚠ Aucun réseau WiFi trouvé.\n"
            "Assurez-vous d'avoir le WiFi activé et les droits root.[/yellow]",
            border_style="yellow"
        ))
        return

    t = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    t.add_column("#", style="dim", width=3)
    t.add_column("SSID", style="bold white", min_width=20)
    t.add_column("BSSID / MAC", style="yellow")
    t.add_column("Signal", min_width=18)
    t.add_column("Canal", style="cyan", justify="center")
    t.add_column("Fréquence", style="cyan")
    t.add_column("Débit Max", style="green")
    t.add_column("Sécurité", style="magenta")
    t.add_column("Mode", style="blue")

    for i, n in enumerate(networks, 1):
        sec = n.get("security", "N/A")
        sec_color = "green" if "WPA2" in sec or "WPA3" in sec else \
                    "yellow" if "WPA" in sec else \
                    "red" if "WEP" in sec or "Open" in sec.lower() else "white"
        t.add_row(
            str(i),
            n.get("ssid", "?"),
            n.get("bssid", "N/A"),
            signal_bar(n.get("signal", "0")),
            n.get("channel", "N/A"),
            n.get("freq", "N/A"),
            n.get("rate", "N/A"),
            f"[{sec_color}]{sec}[/{sec_color}]",
            n.get("mode", "N/A"),
        )

    console.print(t)
    console.print(f"\n[bold]Total: [cyan]{len(networks)}[/cyan] réseau(x) détecté(s)[/bold]\n")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — SCAN ARP (Hôtes sur le réseau local)
# ══════════════════════════════════════════════════════════════════════════════

def get_mac_vendor(mac):
    """Retourne le fabricant à partir de l'adresse MAC."""
    if MANUF_AVAILABLE:
        try:
            p = manuf.MacParser()
            return p.get_manuf(mac) or "Inconnu"
        except Exception:
            pass
    # Lookup OUI manuel basique
    oui = mac.upper().replace("-", ":").split(":")[0][:8]
    oui_db = {
        "00:50:56": "VMware", "00:0C:29": "VMware", "00:1A:11": "Google",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "00:1B:44": "SanNet", "00:16:3E": "Xensource",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    }
    for prefix, vendor in oui_db.items():
        if mac.upper().startswith(prefix):
            return vendor
    return "Inconnu"


def arp_scan(network_cidr, timeout=2):
    """Effectue un scan ARP sur le réseau local."""
    if not SCAPY_AVAILABLE:
        return arp_scan_fallback(network_cidr)

    hosts = []
    try:
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = scapy.srp(packet, timeout=timeout, verbose=False)[0]

        for sent, received in result:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": get_mac_vendor(received.hwsrc),
                "hostname": get_hostname(received.psrc),
                "latency": None,
                "open_ports": []
            })
    except Exception as e:
        console.print(f"[red]Erreur ARP scan: {e}[/red]")
        return arp_scan_fallback(network_cidr)

    return hosts


def arp_scan_fallback(network_cidr):
    """Fallback: ping sweep si Scapy non disponible."""
    hosts = []
    try:
        net = ipaddress.IPv4Network(network_cidr, strict=False)
        ips = list(net.hosts())[:254]

        def ping_host(ip):
            try:
                cmd = ["ping", "-c", "1", "-W", "1", str(ip)] if sys.platform != "win32" \
                      else ["ping", "-n", "1", "-w", "500", str(ip)]
                r = subprocess.run(cmd, capture_output=True, timeout=2)
                if r.returncode == 0:
                    return {
                        "ip": str(ip),
                        "mac": "N/A (sudo requis)",
                        "vendor": "N/A",
                        "hostname": get_hostname(str(ip)),
                        "latency": None,
                        "open_ports": []
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            for result in ex.map(ping_host, ips):
                if result:
                    hosts.append(result)
    except Exception:
        pass
    return hosts


def get_hostname(ip):
    """Résolution DNS inverse."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def scan_ports(ip, ports=None, timeout=0.5):
    """Scan TCP des ports les plus courants."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(s, ip, port)
                open_ports.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Inconnu"),
                    "banner": banner
                })
            s.close()
        except Exception:
            pass
    return open_ports


def grab_banner(sock, ip, port, timeout=1):
    """Tente de récupérer la bannière du service."""
    try:
        if port in [80, 8080, 8443]:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(timeout)
            s2.connect((ip, port))
            s2.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s2.recv(512).decode("utf-8", errors="ignore").split("\r\n")[0]
            s2.close()
            return banner[:80]
        sock.settimeout(timeout)
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        return banner[:80] if banner else ""
    except Exception:
        return ""


def display_hosts(hosts):
    """Affiche les hôtes découverts sur le réseau."""
    console.print(Rule("[bold cyan]◆ HÔTES ACTIFS SUR LE RÉSEAU LOCAL[/bold cyan]", style="cyan"))

    if not hosts:
        console.print(Panel("[yellow]Aucun hôte trouvé. Vérifiez vos droits (sudo).[/yellow]", border_style="yellow"))
        return

    # Tableau principal
    t = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    t.add_column("#", style="dim", width=3)
    t.add_column("Adresse IP", style="bold white")
    t.add_column("Adresse MAC", style="yellow")
    t.add_column("Fabricant", style="cyan")
    t.add_column("Hostname", style="green")
    t.add_column("Ports ouverts", style="magenta", min_width=30)

    for i, h in enumerate(hosts, 1):
        ports_str = ""
        if h.get("open_ports"):
            port_items = []
            for p in h["open_ports"][:10]:
                port_items.append(f"{p['port']}/{p['service']}")
            ports_str = ", ".join(port_items)
            if len(h["open_ports"]) > 10:
                ports_str += f" +{len(h['open_ports'])-10}"
        else:
            ports_str = "[dim]aucun scanné[/dim]"

        t.add_row(
            str(i),
            h["ip"],
            h["mac"],
            h["vendor"],
            h["hostname"],
            ports_str,
        )

    console.print(t)
    console.print(f"\n[bold]Total: [cyan]{len(hosts)}[/cyan] hôte(s) découvert(s)[/bold]\n")

    # Détails ports si trouvés
    for h in hosts:
        if h.get("open_ports"):
            pt = Table(
                title=f"🔓 Ports ouverts sur {h['ip']} ({h['hostname']})",
                box=box.SIMPLE_HEAVY,
                border_style="magenta",
                header_style="bold magenta",
            )
            pt.add_column("Port", style="bold yellow", justify="right", width=8)
            pt.add_column("Service", style="cyan", width=18)
            pt.add_column("Bannière", style="white")
            for p in h["open_ports"]:
                pt.add_row(str(p["port"]), p["service"], p.get("banner", "") or "[dim]—[/dim]")
            console.print(pt)
            console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — INFORMATIONS DNS & RÉSEAU GLOBAL
# ══════════════════════════════════════════════════════════════════════════════

def get_dns_info():
    """Récupère les serveurs DNS configurés."""
    servers = []

    # Linux: /etc/resolv.conf
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
    except Exception:
        pass

    # Windows: ipconfig /all
    if sys.platform == "win32":
        try:
            r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
            for line in r.stdout.split("\n"):
                if "DNS" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        servers.append(ip)
        except Exception:
            pass

    return list(set(servers))


def get_routing_table():
    """Récupère la table de routage."""
    routes = []
    try:
        if sys.platform != "win32":
            r = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in r.stdout.strip().split("\n"):
                if line:
                    routes.append(line.strip())
        else:
            r = subprocess.run(["route", "print"], capture_output=True, text=True)
            for line in r.stdout.split("\n")[4:]:
                if re.match(r'\s+\d', line):
                    routes.append(line.strip())
    except Exception:
        pass
    return routes


def get_public_ip():
    """Récupère l'IP publique et les infos géo."""
    if not REQUESTS_AVAILABLE:
        return {"ip": "N/A (requests non installé)"}
    try:
        r = requests.get("https://ipinfo.io/json", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=5)
        if r.status_code == 200:
            return {"ip": r.json()["ip"]}
    except Exception:
        pass
    return {"ip": "N/A"}


def get_arp_table():
    """Lit la table ARP du système."""
    entries = []
    try:
        if sys.platform != "win32":
            r = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            for line in r.stdout.split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    entries.append({
                        "ip": parts[0],
                        "type": parts[1].strip("()"),
                        "mac": parts[2],
                        "iface": parts[-1] if len(parts) > 3 else "N/A"
                    })
        else:
            r = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            for line in r.stdout.split("\n"):
                m = re.match(r'\s+(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)', line)
                if m:
                    entries.append({
                        "ip": m.group(1),
                        "mac": m.group(2),
                        "type": m.group(3),
                        "iface": "N/A"
                    })
    except Exception:
        pass
    return entries


def get_active_connections():
    """Récupère toutes les connexions réseau actives."""
    connections = []
    for conn in psutil.net_connections(kind="all"):
        try:
            proc_name = psutil.Process(conn.pid).name() if conn.pid else "—"
        except Exception:
            proc_name = "—"

        connections.append({
            "fd": conn.fd,
            "family": str(conn.family).replace("AddressFamily.", ""),
            "type": str(conn.type).replace("SocketKind.", ""),
            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—",
            "status": conn.status,
            "pid": conn.pid or "—",
            "process": proc_name,
        })
    return connections


def display_network_details(dns_servers, public_info, arp_table, routing_table, connections):
    """Affiche les détails réseau globaux."""

    # ── IP publique & géolocalisation ──
    console.print(Rule("[bold cyan]◆ IP PUBLIQUE & GÉOLOCALISATION[/bold cyan]", style="cyan"))
    t = Table(box=box.ROUNDED, border_style="green", header_style="bold green")
    t.add_column("Propriété", style="bold yellow", min_width=20)
    t.add_column("Valeur", style="white")
    for k, v in public_info.items():
        t.add_row(k.upper(), str(v))
    console.print(t)
    console.print()

    # ── DNS ──
    console.print(Rule("[bold cyan]◆ SERVEURS DNS CONFIGURÉS[/bold cyan]", style="cyan"))
    if dns_servers:
        for dns in dns_servers:
            hostname = get_hostname(dns)
            console.print(f"  [cyan]◉[/cyan] [bold]{dns}[/bold]  [dim]({hostname})[/dim]")
    else:
        console.print("[dim]Aucun serveur DNS trouvé[/dim]")
    console.print()

    # ── Table ARP ──
    console.print(Rule("[bold cyan]◆ TABLE ARP (Cache local)[/bold cyan]", style="cyan"))
    if arp_table:
        at = Table(box=box.ROUNDED, border_style="yellow", header_style="bold yellow")
        at.add_column("IP", style="bold white")
        at.add_column("MAC", style="cyan")
        at.add_column("Type", style="green")
        at.add_column("Interface", style="blue")
        for e in arp_table:
            at.add_row(e["ip"], e["mac"], e["type"], e["iface"])
        console.print(at)
    else:
        console.print("[dim]Table ARP vide ou non accessible[/dim]")
    console.print()

    # ── Routage ──
    console.print(Rule("[bold cyan]◆ TABLE DE ROUTAGE[/bold cyan]", style="cyan"))
    if routing_table:
        for route in routing_table[:20]:
            console.print(f"  [cyan]→[/cyan] {route}")
    else:
        console.print("[dim]Table de routage non accessible[/dim]")
    console.print()

    # ── Connexions actives ──
    console.print(Rule("[bold cyan]◆ CONNEXIONS RÉSEAU ACTIVES (Top 30)[/bold cyan]", style="cyan"))
    if connections:
        ct = Table(box=box.ROUNDED, border_style="magenta", header_style="bold magenta", show_lines=False)
        ct.add_column("Proto", style="cyan", width=8)
        ct.add_column("Type", style="blue", width=6)
        ct.add_column("Local", style="white", min_width=22)
        ct.add_column("Distant", style="yellow", min_width=22)
        ct.add_column("État", style="green", width=14)
        ct.add_column("PID", style="dim", width=7)
        ct.add_column("Processus", style="bold", min_width=16)

        shown = [c for c in connections if c["status"] in ("ESTABLISHED", "LISTEN", "SYN_SENT", "CLOSE_WAIT")][:30]
        for c in shown:
            status_color = "green" if c["status"] == "ESTABLISHED" else \
                           "yellow" if c["status"] == "LISTEN" else "red"
            ct.add_row(
                c["family"], c["type"], c["laddr"], c["raddr"],
                f"[{status_color}]{c['status']}[/{status_color}]",
                str(c["pid"]), c["process"]
            )
        console.print(ct)
        console.print(f"\n[dim]Total connexions: {len(connections)} | ESTABLISHED: "
                      f"{sum(1 for c in connections if c['status']=='ESTABLISHED')} | "
                      f"LISTEN: {sum(1 for c in connections if c['status']=='LISTEN')}[/dim]")
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — STATISTIQUES EN TEMPS RÉEL
# ══════════════════════════════════════════════════════════════════════════════

def live_stats(duration=10):
    """Affiche les statistiques réseau en temps réel pendant N secondes."""
    console.print(Rule("[bold cyan]◆ STATISTIQUES RÉSEAU EN TEMPS RÉEL[/bold cyan]", style="cyan"))

    start_io = psutil.net_io_counters()
    start_time = time.time()
    samples = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[bold]{task.fields[speed]}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"Mesure du débit ({duration}s)...",
            total=duration,
            speed="—"
        )
        for i in range(duration):
            time.sleep(1)
            curr_io = psutil.net_io_counters()
            sent_rate = (curr_io.bytes_sent - start_io.bytes_sent) / (i + 1)
            recv_rate = (curr_io.bytes_recv - start_io.bytes_recv) / (i + 1)
            samples.append((sent_rate, recv_rate))
            progress.update(task, advance=1,
                            speed=f"↑ {sent_rate/1024:.1f} KB/s  ↓ {recv_rate/1024:.1f} KB/s")

    end_io = psutil.net_io_counters()
    elapsed = time.time() - start_time

    t = Table(box=box.ROUNDED, border_style="green", header_style="bold green")
    t.add_column("Métrique", style="bold yellow", min_width=28)
    t.add_column("Valeur", style="white")

    total_sent = end_io.bytes_sent - start_io.bytes_sent
    total_recv = end_io.bytes_recv - start_io.bytes_recv
    t.add_row("Durée mesure", f"{elapsed:.1f}s")
    t.add_row("Octets envoyés (session)", f"{total_sent:,} B ({total_sent/1024:.1f} KB)")
    t.add_row("Octets reçus (session)",  f"{total_recv:,} B ({total_recv/1024:.1f} KB)")
    t.add_row("Débit moy. upload",  f"{total_sent/elapsed/1024:.2f} KB/s  ({total_sent/elapsed/1024/1024*8:.2f} Mbps)")
    t.add_row("Débit moy. download", f"{total_recv/elapsed/1024:.2f} KB/s  ({total_recv/elapsed/1024/1024*8:.2f} Mbps)")
    t.add_row("Total paquets envoyés", f"{end_io.packets_sent:,}")
    t.add_row("Total paquets reçus",  f"{end_io.packets_recv:,}")
    t.add_row("Erreurs envoi", str(end_io.errout))
    t.add_row("Erreurs réception", str(end_io.errin))
    t.add_row("Paquets perdus (out)", str(end_io.dropout))
    t.add_row("Paquets perdus (in)",  str(end_io.dropin))
    console.print(t)
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN — ORCHESTRATION
# ══════════════════════════════════════════════════════════════════════════════

def save_report(data: dict):
    """Sauvegarde le rapport en JSON."""
    filename = f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        console.print(f"\n[bold green]✔ Rapport JSON sauvegardé: [cyan]{filename}[/cyan][/bold green]")
    except Exception as e:
        console.print(f"[red]Erreur sauvegarde: {e}[/red]")


def main():
    # Bannière
    console.print(BANNER)
    console.print(Panel(
        f"[bold white]Démarrage: [cyan]{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}[/cyan]  |  "
        f"Hostname: [cyan]{socket.gethostname()}[/cyan]  |  "
        f"OS: [cyan]{sys.platform}[/cyan]  |  "
        f"Python: [cyan]{sys.version.split()[0]}[/cyan][/bold white]\n"
        f"[dim]Scapy: {'✓' if SCAPY_AVAILABLE else '✗'}  |  "
        f"Requests: {'✓' if REQUESTS_AVAILABLE else '✗'}  |  "
        f"manuf: {'✓' if MANUF_AVAILABLE else '✗'}[/dim]",
        border_style="cyan",
        title="[bold cyan]◆ NETWORK SCANNER PRO[/bold cyan]"
    ))
    console.print()

    report = {"timestamp": datetime.now().isoformat(), "hostname": socket.gethostname()}

    # ── 1. Interfaces locales ──
    with console.status("[bold cyan]Analyse des interfaces réseau...", spinner="dots"):
        interfaces = get_local_interfaces()
    display_interfaces(interfaces)
    report["interfaces"] = interfaces

    # ── 2. WiFi ──
    console.print("[bold cyan]Scan des réseaux WiFi...[/bold cyan]")
    wifi_networks = scan_wifi()
    display_wifi(wifi_networks)
    report["wifi_networks"] = wifi_networks

    # ── 3. Scan ARP du réseau local ──
    console.print(Rule("[bold cyan]◆ SCAN DES HÔTES (ARP / Ping Sweep)[/bold cyan]", style="cyan"))
    active_interfaces = [i for i in interfaces if i["is_up"] and i["ipv4"]]

    all_hosts = []
    for iface in active_interfaces:
        for ipv4 in iface["ipv4"]:
            network = ipv4.get("network")
            if network and not network.startswith("127.") and not network.startswith("169."):
                console.print(f"[cyan]→ Scan réseau: [bold]{network}[/bold] (via {iface['name']})[/cyan]")
                with console.status(f"[bold]Scan ARP sur {network}...[/bold]", spinner="dots12"):
                    hosts = arp_scan(network)
                all_hosts.extend(hosts)

    # Scan des ports sur les hôtes trouvés
    if all_hosts:
        console.print(f"\n[bold cyan]Scan des ports sur {len(all_hosts)} hôte(s)...[/bold cyan]")
        with Progress(
            SpinnerColumn(), TextColumn("[bold]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            console=console
        ) as progress:
            task = progress.add_task("Scan des ports...", total=len(all_hosts))
            def scan_host_ports(h):
                h["open_ports"] = scan_ports(h["ip"])
                progress.advance(task)
                return h
            with ThreadPoolExecutor(max_workers=10) as ex:
                all_hosts = list(ex.map(scan_host_ports, all_hosts))

    display_hosts(all_hosts)
    report["hosts"] = all_hosts

    # ── 4. Infos réseau globales ──
    with console.status("[bold cyan]Collecte des infos réseau...", spinner="dots"):
        dns_servers = get_dns_info()
        public_info = get_public_ip()
        arp_table = get_arp_table()
        routing_table = get_routing_table()
        connections = get_active_connections()

    display_network_details(dns_servers, public_info, arp_table, routing_table, connections)
    report["dns_servers"] = dns_servers
    report["public_ip"] = public_info
    report["arp_table"] = arp_table
    report["routing_table"] = routing_table
    report["active_connections"] = len(connections)

    # ── 5. Stats temps réel ──
    live_stats(duration=8)

    # ── Résumé final ──
    console.print(Rule("[bold green]◆ ANALYSE TERMINÉE[/bold green]", style="green"))
    console.print(Panel(
        f"[bold white]✓ Interfaces     : [cyan]{len(interfaces)}[/cyan]\n"
        f"✓ Réseaux WiFi   : [cyan]{len(wifi_networks)}[/cyan]\n"
        f"✓ Hôtes actifs   : [cyan]{len(all_hosts)}[/cyan]\n"
        f"✓ Connexions TCP : [cyan]{len(connections)}[/cyan]\n"
        f"✓ IP publique    : [cyan]{public_info.get('ip', 'N/A')}[/cyan]  "
        f"{public_info.get('city', '')} {public_info.get('country', '')}[/bold white]",
        title="[bold green]RÉSUMÉ[/bold green]",
        border_style="green"
    ))

    # Sauvegarder
    save_report(report)


if __name__ == "__main__":
    # Avertissement droits root
    if os.geteuid() != 0 if hasattr(os, 'geteuid') else False:
        console.print(Panel(
            "[yellow]⚠  Ce script fonctionne mieux avec les droits root (sudo).\n"
            "   Sans root: scan ARP désactivé, certaines interfaces masquées.\n"
            "   Recommandé: [bold]sudo python3 network_scanner.py[/bold][/yellow]",
            border_style="yellow", title="[yellow]AVERTISSEMENT[/yellow]"
        ))
        console.print()

    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]⚡ Interruption par l'utilisateur.[/bold red]")
        sys.exit(0)