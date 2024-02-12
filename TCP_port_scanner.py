import argparse
from scapy.all import (IP, TCP, UDP, ICMP, sr, sr1, send, RandShort)
import textwrap

#syn scan
sport = RandShort()
def syn_scan(target, ports):
    print("syn scan on %s with ports %s" % (target, ports))
    if not isinstance(ports, list):
        ports = [ports]
    for port in ports:
            ans, unans = sr(IP(dst=target) / TCP(sport=sport, dport=port, flags="S"))
            for s, r in ans:
                if r[TCP].flags == 20:
                    print(f"The port {port} is closed: {r[TCP].flags}")
                elif r[TCP].flags == 18:
                    print(f"The port {port} is open: {r[TCP].flags}")
                else:
                    print(port, "TCP packet resp / filtered")
#ack scan
def ack_scan(target, ports):
    print("ack scan on %s with ports %s" % (target, ports))
    if not isinstance(ports, list):
        ports = [ports]
    for port in ports:
            ans, unans = sr(IP(dst=target) / TCP(sport=sport, dport=port, flags="A"))
            for s,r in ans:
                if s[TCP].dport == r[TCP].sport:
                    print("The port %d is unfiltered" % s[TCP].dport)
                elif s in unans:
                    print("The port %d is filtered" % s[TCP].dport)
                else:
                    raise ConnectionError

#null scan	
def null_scan(target, ports):
    print("null scan on %s with ports %s" % (target, ports))
    if not isinstance(ports, list):
        ports = [ports]
    for port in ports:
        ans, unans = sr(IP(dst=target) / TCP(sport=sport, dport=port, flags=""), timeout=1)
        if not ans:
            print(f"The port {port} is unfiltered")
        elif unans:
            print(f"The port {port} is open")
        else:
            for s, r in ans:
                if r[TCP].flags == 0x14:
                    print(f"The port {port} is closed")

#fin scan
def fin_scan(target, ports):
    print("fin scan on %s with ports %s" % (target, ports))
    if not isinstance(ports, list):
        ports = [ports]
    for port in ports:
            ans, unans = sr(IP(dst=target)/TCP(sport=sport, dport=port, flags='F'), timeout=1)
            if not ans:
                print(f"The port {port} is unfiltered")
            elif unans:
                print(f"The port {port} is open")
            else:
                for s, r in ans:
                    if r[TCP].flags == 0x14:
                        print(f"The port {port} is closed")

#xmas scan
def xmas_scan(target, ports):
    print("xmas scan on %s with ports %s" % (target, ports))
    if not isinstance(ports, list):
        ports = [ports]
    for port in ports:
        ans, unans = sr(IP(dst=target)/TCP(sport=sport, dport=port, flags=['F', 'P', 'U']), timeout=1)
        if not ans:
            print(f"The port {port} is unfiltered")
        elif unans:
            print(f"The port {port} is open")
        else:
            for s, r in ans:
                if r[TCP].flags == 0x04:
                    print(f"The port {port} is closed")

#Argomenti
parser = argparse.ArgumentParser(
     description="fucking TCP scanner",
     formatter_class=argparse.RawDescriptionHelpFormatter,
       epilog=textwrap.dedent('''Example:
        TCP_port_scanner.py -t 192.168.123.100 -p 80 -s #SYN scan on port 80
        TCP_port_scanner.py -t 192.168.123.100 -p 80 -a #ACK scan on port 80
        TCP_port_scanner.py -t 192.168.123.100 -p 88 22 -n #NULL scan on ports 80 and 22
        TCP_port_scanner.py -t 192.168.123.100 -p 80 -f #FIN scan on port 80
        TCP_port_scanner.py -t 192.168.123.100 -p 80 22 -x #XMAS scan on ports 80 22'''))
scan_type_group = parser.add_mutually_exclusive_group(required=True)

parser.add_argument("-t", "--target", help="Specify target IP", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify ports (21 23 80 ...)")
scan_type_group.add_argument("-s", "--syn", action="store_true", help="'SYN' flag: starting a connection")
scan_type_group.add_argument("-a", "--ack", action="store_true", help="'ACK' flag: simulating a response for a connection")
scan_type_group.add_argument("-n", "--null", action="store_true", help="No flag: look at the response stupid!")
scan_type_group.add_argument("-f", "--fin", action="store_true", help="'FIN' flag: simulating a end of connection")
scan_type_group.add_argument("-x", "--xmas", action="store_true", help="Scan with 'FIN', 'URG', 'PUSH flags: remember your christmas three?!?!")
args = parser.parse_args()

if __name__ == "__main__":
    target = args.target
    if args.ports:
        ports = args.ports
    else:
        print("You must specify at least one port using -p or --ports.")

    #scan types
    if args.syn:
        syn_scan(target, ports)
    elif args.ack:
        ack_scan(target, ports)
    elif args.null:
        null_scan(target, ports)
    elif args.fin:
        fin_scan(target, ports)
    elif args.xmas:
        xmas_scan(target, ports)
    else:
        raise TypeError
