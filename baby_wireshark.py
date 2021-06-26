#! /usr/bin/python3
import sys
import re
from scapy.all import *

#pcap_ip_grabber takes in a pcap file, grabs all IP addresses, and outputs a list of them
def pcap_ip_grabber(input_file):
  loop = True
  while loop:
    pcap_in = input('What are you looking for?\n[1] Sources\n[2] Destinations\n[3] Protocols\n[4] Keywords\n')
    if pcap_in == '1':
      ip_list = []
      packets = rdpcap(input_file)
      for packet in packets:
        if IP in packet:
          ip_list.append(packet[IP].src)
      return auth_parser(ip_list)
    elif pcap_in == '2':
      ip_list = []
      packets = rdpcap(input_file)
      for packet in packets:
        if IP in packet:
          ip_list.append(packet[IP].dst)
      return auth_parser(ip_list)
    elif pcap_in == '3':
      loop = False
      print('<List of pcap by Protocols here>')
    elif pcap_in == '4':
      loop = False
      print('<Forward over to keyword search function here>')
    else:
      print('Please select a menu option.')

#txt_ip_grabber takes in a text file, grabs all IP addresses, and outputs a list of them
def txt_ip_grabber(input_file):
  re_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
  raw_list = []
  ip_list = []
  #read the file
  with open(input_file) as f:
    line_list = f.read().splitlines()
  #filter out all IP addresses
  for line in line_list:
    raw_list.append(re.findall(re_ip, line))
  raw_list = list(filter(None, raw_list))
  #format raw_list in to a list of strings and output
  ip_list = [item for sublist in raw_list for item in sublist]
  auth_parser(ip_list)

#auth_parser will take in the IP list and count the number of times each one appears
def auth_parser(ip_list):
  total = len(ip_list)
  ip_dict = {}
  sorted_dict = {}
  #count the number of times each IP appears
  for ip in ip_list:
    ip_dict[ip] = ip_dict.get(ip, 0) + 1
  #sort dictionary by value, low to high
  sorted_keys = sorted(ip_dict, key=ip_dict.get)
  for w in sorted_keys:
    sorted_dict[w] = ip_dict[w]
  #format data for output
  print('-------------------------------------')
  print('| IP                          Count |')
  print('-------------------------------------')
  for x in sorted_dict:
    print('| {0: <15} | {1: >15} |'.format(str(x),str(sorted_dict[x])))
  print('-------------------------------------')
  print('| Total {0: >27} |'.format(str(total)))
  print('-------------------------------------')

#main takes in a file, passes it through ip_grabber, then through auth_parser
def main():
  input_file = sys.argv[1]
  loop = True
  while loop:
    input0 = input('What type of file is this?\n[1] txt\n[2] pcap\n')
    if input0 == '1':
      return(txt_ip_grabber(input_file))
    elif input0 == '2':
      return(pcap_ip_grabber(input_file))
    else:
      print('Please select [1] or [2].')

main()
