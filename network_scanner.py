#!/usr/bin/env python3

from argparse import *
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from termcolor import colored, cprint


def get_arg():
    parser = ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter the target ip address (range)")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    return parser.parse_args()


def scanner(ip):
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_req
    ans = srp(arp_broadcast, timeout=2, verbose=False)[0]

    result_list = []
    for element in ans:
        result_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        result_list.append(result_dict)

    return result_list


def print_result(res_lst):
    print(colored("IP Address\t\tMAC Address", "red", attrs=['bold']) + "\n-----------------------------------------")
    for result in res_lst:
        # print(colored(result["ip"] + "\t\t" + result["mac"], "yellow"))
        cprint(result["ip"] + "\t\t" + result["mac"], "yellow")


try:
    target_ip = get_arg()
    cprint("[+] Welcome to Network scanner", "cyan")
    scanner_result = scanner(target_ip.target)
    print_result(scanner_result)
except KeyboardInterrupt:
    cprint("\nProgram Terminated\nCause: keyboard interruption", "red")
