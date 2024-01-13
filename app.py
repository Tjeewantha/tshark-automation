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

print(all_protocols(tcp))
print(all_protocols(udp))
         
