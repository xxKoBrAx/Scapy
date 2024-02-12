from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

netSSID = 'testSSID' #Fake AP name
iface = 'wlo1'   #Your interface

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', #type=0 management frame, subtype=8 beacon frame #addr1=dest addr2=src addr3=APaddr
addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
beacon = Dot11Beacon(cap='ESS+privacy')  #ESS=802.11 network privacy=network protected
essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
rsn = Dot11Elt(ID='RSNinfo', info=(   #to implement WPA2
'\x01\x00'         #RSN Version 1
'\x00\x0f\xac\x02' #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'         #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04' #AES Cipher
'\x00\x0f\xac\x02' #TKIP Cipher
'\x01\x00'         #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02' #Pre-Shared Key
'\x00\x00'))       #RSN Capabilities (no extra capabilities)

frame = RadioTap()/dot11/beacon/essid/rsn

frame.show()
print("\nHexDump of frame:")
hexdump(frame)   #from binary to hexadecimal
input("\nPress enter to start\n")

sendp(frame, iface=iface, inter=0.100, loop=1) #inter=0.100” “loop=1” a frame sent every 100 milliseconds until the program is exited
