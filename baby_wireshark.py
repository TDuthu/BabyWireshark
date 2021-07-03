#! /usr/bin/python3
import re
import sys
from scapy.all import *
global re_ip
re_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

#main will take in a file and forward it to the correct parser
def main():
  print(shark)
  if len(sys.argv) != 2:
    sys.exit('Please execute with one file next time.')
  else:
    input_file = sys.argv[1]
    loop = True
    while loop:
      main_menu = input('What type of file is this?\n[1] txt\n[2] pcap\n')
      if main_menu == '1':
        return(txt_parser(input_file))
      elif main_menu == '2':
        global packets
        packets = rdpcap(input_file)
        return(pcap_parser(packets))
      else:
        print('Please select a valid menu option.')

#txt_parser will take in a text file, grab all IP addresses, and forward to format_func
def txt_parser(input_file):
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
  format_func(ip_list)

#pcap_parser will take in packets and forward them to the correct function
def pcap_parser(packets):
  print(shark)
  loop = True
  while loop:
    pcap_menu = input('What are you looking for?\n[1] Sources\n[2] Destinations\n[3] Protocols\n[4] IP Search\n')
    if pcap_menu == '1':
      ip_list = []
      for packet in packets:
        if IP in packet:
          ip_list.append(packet[IP].src)
      return format_func(ip_list)
    elif pcap_menu == '2':
      ip_list = []
      for packet in packets:
        if IP in packet:
          ip_list.append(packet[IP].dst)
      return format_func(ip_list)
    elif pcap_menu == '3':
      return protocols(packets)
    elif pcap_menu == '4':
      return ip_search(packets)
    else:
      print('Please select a valid menu option.')

#protocols will take in packets and filter by protocol
def protocols(packets):
  print(shark,'\n',packets)
  loop = True
  while loop:
    proto_menu = input('Which type of protocol?\n[1] TCP \n[2] UDP \n[3] ICMP \n[4] Other\n')
    if proto_menu == '1':
      TCP_count=0
      for packet in packets:
        if TCP in packet:
          TCP_count+=1
          print(packet.summary,'\n')
      print('The total amount of TCP connections is: '+str(TCP_count))
      loop=False
    elif proto_menu == '2':
      UDP_count=0
      for packet in packets:
        if UDP in packet:
          UDP_count+=1
          print(packet.summary,'\n')
      print('The total amount of UDP connections is: '+str(UDP_count))
      loop=False
    elif proto_menu == '3':
      ICMP_count=0
      for packet in packets:
        if ICMP in packet:
          ICMP_count+=1
          print(packet.summary,'\n')
      print('The total amount of ICMP connections is: '+str(ICMP_count))
      loop=False
    elif proto_menu == '4':
      Other_count=0
      for packet in packets:
        if TCP not in packet and UDP not in packet and ICMP not in packet:
          Other_count+=1
          print(packet.summary,'\n')
      print('The total amount of other connections is: '+str(Other_count))
      loop=False
    else:
      print('Please enter a valid menu option.')

#ip_search will take in packets and search for all packets matching user's ip_input
def ip_search(packets):
  print(shark)
  ip_input = input('Enter an IP address: ')
  if re.match(re_ip, ip_input) != None:
    print('I found these packets with that IP:\n')
    for packet in packets:
      if IP in packet:
        if packet[IP].src == ip_input or packet[IP].dst == ip_input:
          print(packet.summary,'\n')
  else:
    ip_search(packets)

#format_func will take in ip_list and count the number of times each one appears
def format_func(ip_list):
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

global shark
shark = '''
                                                                ██████████                                      
                                                            ██▓▓▒▒▒▒▒▒▒▒▒▒▓▓                                    
                                                        ████▒▒▒▒▒▒▒▒▒▒▒▒██                                      
                                                      ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓░░                                      
                                                    ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒██                                          
                                                  ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██                                          
                                                ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██                                            
                    ▓▓██▓▓████░░░░██░░░░░░░░▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██                                        ▓▓██
              ▓▓▓▓██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████                                  ████▒▒██
          ▓▓██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████                            ██▒▒▒▒▒▒██
      ████▒▒░░▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░▒▒████                      ██▒▒▒▒▒▒██  
    ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓                  ██▒▒▒▒▒▒██  
░░██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████            ██▒▒▒▒▒▒██    
  ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓██        ██▒▒▒▒▒▒██    
  ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░▒▒▓▓▓▓  ▓▓▒▒▒▒▒▒▓▓██    
░░██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒██      
░░██▓▓▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒██▒▒▒▒██▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓██      
    ██▒▒▒▒▒▒▓▓████████████████████████▓▓██▒▒▒▒▒▒▒▒▒▒██▒▒▒▒██▓▓▒▒██▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██        
    ██▒▒▒▒▒▒▒▒██  ▓▓  ▓▓  ▓▓░░▓▓░░▓▓░░▓▓██▒▒▒▒▒▒▒▒▒▒██▒▒▒▒██▒▒▒▒██▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██        
      ██▒▒▒▒▒▒▒▒██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▒▒▒▒▒▒██▓▓▒▒██▓▓▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒██          
      ██▒▒▒▒▒▒▒▒██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▒▒▒▒▒▒▒▒▓▓▒▒▒▒▓▓▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓        
        ██▒▒▒▒▒▒▓▓██  ▓▓  ▓▓  ▓▓  ▓▓██▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░▒▒▒▒▒▒▒▒▓▓      
          ██▓▓▒▒▒▒▓▓████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░██▓▓▒▒▒▒▒▒██      
            ██▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░████  ██▒▒▒▒▒▒▒▒██    
              ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░▓▓██        ██▒▒▒▒▒▒██    
                ██▒▒▒▒▒▒░░░░░░░░░░░░▒▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒░░░░░░░░████            ██▓▓▒▒▒▒██    
                  ██▓▓░░░░░░░░░░░░░░░░░░▒▒▒▒▓▓██▓▓▒▒▒▒▒▒▒▒▒▒▒▒██▓▓▒▒▒▒░░░░░░░░████                  ██▓▓▒▒▒▒██  
                    ██▒▒░░░░░░░░░░░░░░░░░░░░░░██▓▓▒▒▒▒▒▒▒▒▒▒▒▒██░░░░░░░░░░████                        ████▒▒██  
                      ██████░░░░░░░░░░░░░░░░░░██▓▓▒▒▒▒▒▒▒▒▒▒▒▒██░░░░░░████                                ████  
                      ██▒▒▓▓██████░░░░░░░░░░░░░░██▓▓▒▒▒▒▒▒▒▒▒▒████████                                          
                      ██▒▒▒▒▓▓▓▓▓▓████▒▒▒▒▒▒██▓▓████▒▒▒▒▒▒▒▒▒▒▒▒██                                              
                        ██▒▒▓▓▓▓▓▓██                ██▒▒▒▒▒▒▒▒▒▒██                                              
                        ██▒▒▓▓▓▓▓▓██                  ██▓▓▒▒▒▒▒▒▒▒██                                            
                          ██▒▒▓▓▓▓██                    ██▓▓▒▒▒▒▒▒██                                            
                            ██▒▒▓▓▓▓██                      ████▓▓▓▓██                                          
                              ████████                          ██████                                          '''

main()
