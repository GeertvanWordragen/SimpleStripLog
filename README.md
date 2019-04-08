# SimpleStripLog

This tool performs a simple SSL stripping attack, based on the ideas presented by Moxie Marlinspike in [2009](https://www.blackhat.com/presentations/bh-dc-09/Marlinspike/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf).

##Requirements

The tool makes use of the following programs and modules, hence make sure that they are installed on your system when you want to use it.
* [Python](https://www.python.org/)
* [Scapy](https://scapy.net/)
* [argparse](https://docs.python.org/3/library/argparse.html)


##Setup

First, in order to prevent your system from sending RST packets as an answer to packets received from victim clients and servers, execute the following command.

    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

Download/clone the code in this repository to the desired destination on your system.

Execute the following command to start

    python sslstrip.py [-h] [-i/--interface IFA] victimIP serverIP attackerIP
    
The victimIP, serverIP and attackerIP arguments are always required, unless you want to open the help page with -h. The arguments stand for the following:
* -h: opens the help page
* -i IFA: give the preferred interface over which the host will send packets
* victimIP: IP of victim client
* serverIP: IP of victim server
* attackerIP: IP of attacker/host
