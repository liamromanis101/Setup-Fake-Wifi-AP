#!/usr/bin/env python3
import ipaddress
import os
import shutil
import subprocess
import sys
from pathlib import Path

HOSTAPD_CONF = Path("/etc/hostapd/hostapd.conf")
HOSTAPD_DEFAULT = Path("/etc/default/hostapd")
DNSMASQ_DROPIN = Path("/etc/dnsmasq.d/ap.conf")
SYSCTL_CONF = Path("/etc/sysctl.conf")

def sudo():
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo).")
        sys.exit(1)

def run(cmd, check=True):
    """Run a system command safely (no shell=True)."""
    print(f"[+] $ {' '.join(cmd)}")
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0:
        print(result.stdout.strip())
        print(result.stderr.strip())
        if check:
            sys.exit(result.returncode)
    return result

def apt_install(pkgs):
    run(["apt-get", "update"], check=False)
    run(["apt-get", "install", "-y"] + pkgs)

def ensure_packages():
    required = ["hostapd", "dnsmasq", "iptables", "dhclient"]
    missing = [pkg for pkg in required if shutil.which(pkg) is None]
    if missing:
        print(f"[+] Installing missing packages: {' '.join(missing)}")
        apt_install(missing)

def disable_network_manager():
    print("[+] Disabling NetworkManager")
    run(["systemctl", "stop", "NetworkManager"], check=False)
    run(["systemctl", "disable", "NetworkManager"], check=False)

def configure_ethernet_dhcp(eth_iface):
    """
    Bring up the Ethernet interface and ensure it has a DHCP IPv4 address.
    """
    print(f"[+] Configuring {eth_iface} for DHCP (uplink)")
    run(["ip", "link", "set", eth_iface, "up"], check=False)
    run(["dhclient", "-r", eth_iface], check=False)  # release any old lease
    result = run(["dhclient", "-4", eth_iface], check=False)
    if result.returncode == 0:
        print(f"[+] DHCP request sent successfully on {eth_iface}")
    else:
        print(f"[!] DHCP failed on {eth_iface}. Check cable or router DHCP server.")

def configure_hostapd(wifi_iface, ssid="MyAccessPoint", passphrase="SuperSecurePass", channel="6"):
    content = f"""interface={wifi_iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase={passphrase}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    HOSTAPD_CONF.parent.mkdir(parents=True, exist_ok=True)
    HOSTAPD_CONF.write_text(content)
    print(f"[+] Wrote {HOSTAPD_CONF}")

    # Ensure /etc/default/hostapd points to our config
    text = HOSTAPD_DEFAULT.read_text() if HOSTAPD_DEFAULT.exists() else ""
    lines = [l for l in text.splitlines() if not l.startswith("DAEMON_CONF=")]
    lines.append(f'DAEMON_CONF="{HOSTAPD_CONF}"')
    HOSTAPD_DEFAULT.write_text("\n".join(lines) + "\n")

    run(["systemctl", "unmask", "hostapd"], check=False)
    run(["systemctl", "enable", "hostapd"])

def parse_network(arg):
    """
    Accept:
      - CIDR (e.g. 52.112.0.0/14)
      - or explicit range: 192.168.12.10,192.168.12.100
    Returns: gateway_ip, dhcp_start, dhcp_end, netmask
    """
    try:
        net = ipaddress.ip_network(arg.strip(), strict=False)
        hosts = list(net.hosts())
        if len(hosts) < 10:
            raise ValueError(f"Network {net} too small for DHCP range.")
        gateway = str(hosts[0])

        # Pick a sensible DHCP range within network
        start_index = max(10, 1)
        end_index = min(len(hosts) - 2, start_index + 200)
        dhcp_start = str(hosts[start_index])
        dhcp_end = str(hosts[end_index])
        netmask = str(net.netmask)
        return gateway, dhcp_start, dhcp_end, netmask
    except ValueError:
        # Try DHCP range form
        if "," not in arg:
            print(f"[!] Invalid network/range format: {arg}")
            sys.exit(1)
        start, end = [x.strip() for x in arg.split(",", 1)]
        s_ip = ipaddress.ip_address(start)
        e_ip = ipaddress.ip_address(end)
        net = ipaddress.ip_network(f"{s_ip}/24", strict=False)
        gateway = str(ipaddress.IPv4Address(int(net.network_address) + 1))
        return gateway, start, end, str(net.netmask)

def configure_dnsmasq(wifi_iface, dhcp_start, dhcp_end, gateway, netmask):
    """
    Create a valid dnsmasq drop-in config with explicit IP range.
    """
    conf = Path("/etc/dnsmasq.conf")
    if conf.exists():
        lines = conf.read_text().splitlines()
        new_lines = []
        for line in lines:
            if line.strip().startswith("dhcp-range="):
                new_lines.append("# " + line)
            else:
                new_lines.append(line)
        conf.write_text("\n".join(new_lines) + "\n")

    DNSMASQ_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    content = f"""# Auto-generated WiFi AP config
interface={wifi_iface}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},{netmask},12h
dhcp-option=3,{gateway}
dhcp-option=6,1.1.1.1,8.8.8.8
"""
    DNSMASQ_DROPIN.write_text(content)
    print(f"[+] Wrote {DNSMASQ_DROPIN}")

    # Validate before enabling
    test = subprocess.run(["dnsmasq", "--test"], text=True, capture_output=True)
    if test.returncode != 0:
        print("[!] dnsmasq configuration error:\n" + test.stderr)
        sys.exit(1)
    else:
        print("[+] dnsmasq syntax check passed")

    subprocess.run(["systemctl", "enable", "dnsmasq"], check=False)

def configure_wifi_ip(wifi_iface, gateway, netmask):
    print(f"[+] Assigning {gateway}/{netmask} to {wifi_iface}")
    run(["ip", "addr", "flush", "dev", wifi_iface], check=False)
    cidr = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    run(["ip", "addr", "add", f"{gateway}/{cidr}", "dev", wifi_iface])
    run(["ip", "link", "set", wifi_iface, "up"])

def enable_ip_forwarding():
    print("[+] Enabling IPv4 forwarding")
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    lines = []
    found = False
    if SYSCTL_CONF.exists():
        lines = SYSCTL_CONF.read_text().splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith("net.ipv4.ip_forward"):
                lines[i] = "net.ipv4.ip_forward=1"
                found = True
    if not found:
        lines.append("net.ipv4.ip_forward=1")
    SYSCTL_CONF.write_text("\n".join(lines) + "\n")

def setup_nat(wifi_iface, eth_iface):
    if shutil.which("iptables") is None:
        print("[!] iptables not found. Please install iptables or use nftables.")
        sys.exit(1)

    print(f"[+] Configuring NAT {wifi_iface} -> {eth_iface}")
    run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", eth_iface, "-j", "MASQUERADE"], check=False)
    run(["iptables", "-D", "FORWARD", "-i", eth_iface, "-o", wifi_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
    run(["iptables", "-D", "FORWARD", "-i", wifi_iface, "-o", eth_iface, "-j", "ACCEPT"], check=False)

    run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", eth_iface, "-j", "MASQUERADE"])
    run(["iptables", "-A", "FORWARD", "-i", eth_iface, "-o", wifi_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    run(["iptables", "-A", "FORWARD", "-i", wifi_iface, "-o", eth_iface, "-j", "ACCEPT"])

    if shutil.which("netfilter-persistent"):
        print("[+] Saving iptables rules persistently")
        run(["netfilter-persistent", "save"], check=False)
    elif shutil.which("iptables-save"):
        Path("/etc/iptables").mkdir(parents=True, exist_ok=True)
        Path("/etc/iptables/rules.v4").write_text(subprocess.check_output(["iptables-save"], text=True))

def restart_services():
    run(["systemctl", "restart", "dnsmasq"])
    run(["systemctl", "restart", "hostapd"])

def status_services():
    print("\n[+] Checking service status\n")
    run(["systemctl", "status", "dnsmasq", "--no-pager"], check=False)
    run(["systemctl", "status", "hostapd", "--no-pager"], check=False)

def usage():
    print(
        "Usage: sudo python3 setup_wifi_ap.py <WiFi_IFACE> <Ethernet_IFACE> <CIDR_or_DHCP_range> [SSID] [PASS] [CHANNEL]\n"
        "Examples:\n"
        "  sudo python3 setup_wifi_ap.py wlan0 eth0 192.168.50.0/24 MyAP MyPass123 6\n"
        "  sudo python3 setup_wifi_ap.py wlan0 eth0 10.10.0.0/20\n"
        "  sudo python3 setup_wifi_ap.py wlan0 eth0 192.168.12.10,192.168.12.100\n"
    )

def main():
    sudo()
    if len(sys.argv) < 4:
        usage()
        sys.exit(1)

    wifi_iface = sys.argv[1]
    eth_iface = sys.argv[2]
    ip_arg = sys.argv[3]
    ssid = sys.argv[4] if len(sys.argv) > 4 else "MyAccessPoint"
    psk = sys.argv[5] if len(sys.argv) > 5 else "SuperSecurePass"
    channel = sys.argv[6] if len(sys.argv) > 6 else "6"

    ensure_packages()
    disable_network_manager()
    configure_ethernet_dhcp(eth_iface)

    gateway, dhcp_start, dhcp_end, netmask = parse_network(ip_arg)
    configure_hostapd(wifi_iface, ssid, psk, channel)
    configure_dnsmasq(wifi_iface, dhcp_start, dhcp_end, gateway, netmask)
    configure_wifi_ip(wifi_iface, gateway, netmask)
    enable_ip_forwarding()
    setup_nat(wifi_iface, eth_iface)
    restart_services()
    status_services()

    print("\n[✅] WiFi Access Point setup complete.")
    print(f"    SSID: {ssid}")
    print(f"    Gateway: {gateway}  DHCP: {dhcp_start}–{dhcp_end}  Netmask: {netmask}")
    print(f"    WiFi iface: {wifi_iface}  Ethernet iface: {eth_iface}")

if __name__ == "__main__":
    main()
