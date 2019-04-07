from colores import colores
from scapy.all import *

#check whether ip conforms to ipv4
def ipv4(ip):
    groups = ip.split('.')
    if len(groups) != 4 or any(not x.isdigit() for x in groups):
        return False
    return all(0 <= int(y) < 256 for y in groups)

#validate input from arguments
def validate(args):
    if not args.victimIP or not args.serverIP or not args.attackerIP:
        return False
    
    if not ipv4(args.victimIP):
        print args.victimIP + colores.ORANGE + ': IP of victim client is not a valid IP address\n' + colores.RED + 'End of program' + colores.RESETALL
        return False
    
    if not ipv4(args.serverIP):
        print args.serverIP + colores.ORANGE + ': IP of victim client is not a valid IP address\n' + colores.RED + 'End of program' + colores.RESETALL
        return False
    
    if not ipv4(args.attackerIP):
        print args.attackerIP + colores.ORANGE + ': IP of attacker is not a valid IP address\n' + colores.RED + 'End of program' + colores.RESETALL
        return False

    #check if args.ifa is present at attacker
    if args.ifa:
        found = False
        for i in get_if_list():
            if i == args.ifa:
                found = True
                break
        if not found:
            print args.ifa + colores.ORANGE + ': Interface is not present\n' + colores.RED + 'End of program' + colores.RESETALL
            return False

    return True
