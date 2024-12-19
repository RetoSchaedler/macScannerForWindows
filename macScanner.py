import scapy.all as scapy
import ipaddress
import psutil
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_up_networks():
    psutil_stats = psutil.net_if_stats()
    psutil_addrs = psutil.net_if_addrs()

    print("=== Verfügbare Schnittstellen ===")
    print(list(psutil_addrs.keys()))

    print("\n=== Schnittstellenstatus ===")
    for iface, stats in psutil_stats.items():
        status = 'up' if stats.isup else 'down'
        print(f"{iface}: {status}")

    print("\n=== Überprüfung der Schnittstellen ===")
    for iface, stats in psutil_stats.items():
        if stats.isup:
            print(f"\nÜberprüfe Schnittstelle: {iface} (aktiv)")
            addrs = psutil_addrs.get(iface, [])
            if not addrs:
                print(f"  Keine Adressen für Schnittstelle '{iface}'.")
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    print(f"  IP: {ip}, Netmask: {netmask}")
                    if ip and netmask:
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            print(f"  Hinzugefügtes Netzwerk: {network}")
                        except ValueError:
                            print(f"  Warnung: Ungültiges Netzwerk für IP {ip} und Netmask {netmask}.")
                            continue
                        # Benutzerabfrage hinzufügen und direkt scannen
                        while True:
                            response = input(f"  Möchten Sie das Netzwerk {network} für die Schnittstelle '{iface}' scannen? (y/n): ").strip().lower()
                            if response in ['y', 'yes']:
                                print(f"  Schnittstelle '{iface}' mit Netzwerk '{network}' wird gescannt.")
                                scan_network(network)
                                break
                            elif response in ['n', 'no']:
                                print(f"  Schnittstelle '{iface}' mit Netzwerk '{network}' wird übersprungen.")
                                break
                            else:
                                print("  Ungültige Eingabe. Bitte geben Sie 'y' oder 'n' ein.")
    return

def arp_scan(ip):
    try:
        arp_request = scapy.ARP(pdst=str(ip))
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        for sent, received in answered_list:
            return (received.psrc, received.hwsrc)
    except Exception as e:
        # Fehler protokollieren
        print(f"Fehler beim Scannen von {ip}: {e}")
        return None

def scan_network(network):
    print(f"\n=== Scanne Netzwerk: {network} ===")
    active_hosts = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(arp_scan, ip): ip for ip in network.hosts()}
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                active_hosts.append(result)
                print(f"IP: {result[0]} \t MAC: {result[1]}")
    if not active_hosts:
        print("  Keine aktiven Hosts im Netzwerk gefunden.")
    else:
        print(f"=== Scan abgeschlossen für Netzwerk: {network} ===\n")

def main():
    get_up_networks()

if __name__ == "__main__":
    main()
