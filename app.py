#!/usr/bin/python3

import subprocess
from argparse import ArgumentParser
from pathlib import Path
import re

def get_tcp_packets(pcap):
    tcp_dic = {}
    command = subprocess.Popen(['tshark', '-n', '-r', pcap, '-Y' 'tcp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, error = command.communicate()
    l = output.split('\n')[0:-1]
    for i in l: 
        k = re.split('\s+', i)[1:] 
        tcp_dic['tcp_frame'] = k[0]
        tcp_dic.setdefault(k[0], {}).setdefault('time',k[1]) 
        tcp_dic.setdefault(k[0], {}).setdefault('src_add',k[2])
        tcp_dic.setdefault(k[0], {}).setdefault('dst_add',k[4])
        tcp_dic.setdefault(k[0], {}).setdefault('protocol',k[5])
        # print(tcp_dic[tcp_dic['tcp_frame']])
    if error : print("check get_tcp_packet funtion")

def get_udp_packets(pcap):
    udp_dic = {}
    command = subprocess.Popen(['tshark', '-n', '-r', pcap, '-Y' 'udp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
    output, error = command.communicate()
    l = output.split('\n')[0:-1]
    for i in l: 
        k = re.split('\s+', i)[1:]
        udp_dic['udp_frame'] = k[0]
        udp_dic.setdefault(k[0], {}).setdefault('time',k[1]) 
        udp_dic.setdefault(k[0], {}).setdefault('src_add',k[2])
        udp_dic.setdefault(k[0], {}).setdefault('dst_add',k[4])
        udp_dic.setdefault(k[0], {}).setdefault('protocol',k[5])
        # print(udp_dic[udp_dic['tcp_frame']]) 
    return udp_dic
    if error : print("check get_tcp_packet funtion")




parser = ArgumentParser()
parser.add_argument('pcap', help="select your file.pcap")
args = parser.parse_args()

file = args.pcap

print(get_udp_packets(file)[get_udp_packets(file)['udp_frame']])
# print(get_tcp_packets(file))
 
# print(get_udp_packets(file)[5])
# print(get_tcp_packets(file)[5])       