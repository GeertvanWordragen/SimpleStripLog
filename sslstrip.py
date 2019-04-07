import argparse
from scapy.all import *
import sys
from validate import validate

#collect input from command line
parser = argparse.ArgumentParser(description = 'SSL stripping tool')
parser.add_argument('victimIP', help = 'IP of victim client', metavar = 'victimIP')
parser.add_argument('serverIP', help = 'IP of HTTPS server', metavar = 'serverIP')
parser.add_argument('attackerIP', help = 'IP of attacker', metavar = 'attackerIP')
args = parser.parse_args()

#validate input from command line
if not validateInput(args):
    sys.exit()