#!/usr/bin/python3

import subprocess
from argparse import ArgumentParser
from pathlib import Path
import re
from prettytable import PrettyTable


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
def ms_dns_info(): #switch between llmnr/netbios
    l = ('llmnr', 'nbns')  
    for i in l:
        if i.upper() in all_protocols(udp):
            for sw in ('ip','ipv6'):
                lists = []
                print("-"*50, sw,'-',i.upper(),"-"*50)
                # if you add a field to cmd, remember to update prettytable fields
                t = PrettyTable(['Src_Add', 'Src_Port', 'Dst_Add', 'Dst_Port', 'Is_Query','Query_Name'])
                cmd0 = ['-Y', i + '&& (dns.retransmission == True)', '-T', 'fields', '-e', sw+'.src', '-e', 'udp.srcport', '-e', 'ip.dst',
                    '-e', sw+'.dst','-e', 'udp.dstport','-e','dns.count.queries', '-e', 'dns.qry.name']
                cmd1 =[]
                process = tshark_exec(cmd0, file)
                for j in process:
                    k = re.split('\s+', j)
                    if j[0] == '\t':
                        process.remove(j)
                    elif k[4] == '0':
                        process.remove(j)
                    else:
                        lists.append(k)
                t.add_rows(lists)
                print(t)
                # src_add, dst_add = set()

                # for list in lists:
                #     src_add.add(list[0])
                #     dst_add.add(list[2])
                # print(src_add, dst_add)
                lists = [] # to refresh exsisting list to empty   
        else:
            print(f"{i.upper()} not found in {file}")

# another request table should be added    
ms_dns_info()

