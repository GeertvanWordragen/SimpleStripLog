import argparse
from scapy.all import *
import sys
from validate import validates

#collect input from command line
parser = argparse.ArgumentParser(description = 'SSL stripping tool')
parser.add_argument('-i', '--interface', help = 'Preferred interface for sniffing packets', dest = 'ifa', action = 'store', default = None)
parser.add_argument('-t', '--timeout', help = 'Preferred timeout for sniffing packets, default = 60', dest = 'to', action = 'store', default = 60)
parser.add_argument('-o', '--output', help = 'File to write sniffed packets to', dest = 'out', action = 'store', default = 'sslstrip.pcap')
args = parser.parse_args()

#validate input from command line
if not validates(args):
    sys.exit()

if args.ifa:
    #sniff on preferred interface for preferred time
    packets = sniff(iface = args.ifa, timeout = args.to)
else:
    #sniff on conf.iface for preferred time
    packets = sniff(timeout = args.to)

#save sniffed packets
wrpcap(args.out, packets)
