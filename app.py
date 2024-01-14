#!/usr/bin/python3

import subprocess
from argparse import ArgumentParser
from pathlib import Path
import re

def parser():
    parser = ArgumentParser()
    parser.add_argument('pcap', help="select your file.pcap")
    args = parser.parse_args()
    return args

file = parser().pcap

def tshark_exec(cmd, pcap):
    imut_cmd = ['tshark', '-n', '-r', pcap]
    command = subprocess.Popen(imut_cmd + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
    output, error = command.communicate()
    if error :
        print("check given command!! ->", *(imut_cmd+cmd))
        return str(error)
    else:
        k = re.split('\n', output)[:-2]
        return k        

udp = ['-Y', 'udp']
tcp = ['-Y', 'tcp']
def all_protocols(proto):
    protocols = []
    for i in tshark_exec(proto, file):
        temp = re.findall('\S+', i)[5]
        if temp not in protocols:
            protocols.append(temp)
    return protocols

'''
Adversaries can spoof an authoritative source for name resolution on a victim network by responding to 
LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host
'''   
def ms_dns_info(): #sw = llmnr/netbios
    l = ('llmnr', 'nbns')
    for i in l:
        if i.upper() in all_protocols(udp):
            print("-"*50, 'IPv4-',i.upper(),"-"*50)
            cmd = ['-Y', i + '&& (dns.retransmission == True)', '-T', 'fields', '-e', 'ip.src', '-e', 'udp.srcport', '-e', 'ip.dst',
                    '-e', 'udp.dstport','-e','dns.count.queries', '-e', 'dns.qry.name', '-e', 'dns.count.answers', '-E', 'header=y']
            process = tshark_exec(cmd, file)
            for j in process:
                if j[0] == '\t':
                    process.remove(j)
                else:
                    print(j)
            print("-"*50, 'IPv6-',i.upper(),"-"*50)
            cmd = ['-Y', i + '&& (dns.retransmission == True)', '-T', 'fields', '-e', 'ipv6.src', '-e', 'udp.srcport', '-e', 'ip.dst',
                    '-e', 'udp.dstport','-e','dns.count.queries', '-e', 'dns.qry.name', '-e', 'dns.count.answers', '-E', 'header=y']
            process = tshark_exec(cmd, file)
            for k in process:
                if k[0] == '\t':
                    process.remove(k)
                else:
                    print(k)
        else:
            print(f"{i.upper()} not found in {file}")


ms_dns_info()
         
