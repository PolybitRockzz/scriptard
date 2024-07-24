import os
from scapy.all import sniff, IP, TCP, UDP, Ether
import json
from colorama import just_fix_windows_console
from colorama import Fore, Back, Style

line_length = os.get_terminal_size().columns

def read_addresses():
  # Read the JSON data from the file
  with open("addresses.json", "r") as file:
    return json.load(file)

all_addrs = read_addresses()

def find_name_by_mac(mac_address):
  # Search for the MAC address in the JSON array
  for entry in all_addrs:
    if entry["value"] == mac_address:
      return entry["name"]
    
  return mac_address

# Define a callback function to process packets
def packet_callback(packet):
    if packet.haslayer(Ether):
        src_mac = find_name_by_mac(str(packet['Ether'].src).upper())
        dst_mac = find_name_by_mac(str(packet['Ether'].dst).upper())
        printing_str = f"{Style.BRIGHT}{Fore.WHITE}[ {src_mac} -> {dst_mac}"
        print(f"{Back.LIGHTCYAN_EX}{printing_str}{' ' * (line_length-len(printing_str))}]{Style.RESET_ALL}")
        if packet.haslayer(IP):
          src_ip = packet[IP].src
          dst_ip = packet[IP].dst
          print(f"  {Fore.LIGHTBLACK_EX}Source IP: {src_ip} -> Destination IP: {dst_ip}{Style.RESET_ALL}")
        if packet.haslayer(TCP):
          src_port = packet[TCP].sport
          dst_port = packet[TCP].dport
          flags = packet[TCP].flags
          print(f"  > {Fore.LIGHTBLACK_EX}Protocol: TCP{Style.RESET_ALL} ", end='')
          if flags == 'S':
            print(f"{Fore.LIGHTCYAN_EX}Request (SYN){Style.RESET_ALL}")
          elif flags == 'SA':
            print(f"{Fore.LIGHTGREEN_EX}Response (SYN-ACK){Style.RESET_ALL}")
          elif flags == 'A':
            print(f"{Fore.LIGHTGREEN_EX}Response (ACK){Style.RESET_ALL}")
          elif 'F' in flags:
            print(f"{Fore.LIGHTRED_EX}Finishing (FIN){Style.RESET_ALL}")
          print(f"  > {Fore.LIGHTBLACK_EX}Source Port: {src_port} -> Destination Port: {dst_port}{Style.RESET_ALL}")
        elif packet.haslayer(UDP):
          src_port = packet[UDP].sport
          dst_port = packet[UDP].dport
          print(f"  > {Fore.LIGHTBLACK_EX}Protocol: UDP{Style.RESET_ALL}")
          print(f"  > {Fore.LIGHTBLACK_EX}Source Port: {src_port} -> Destination Port: {dst_port}{Style.RESET_ALL}")

if __name__ == "__main__":
  just_fix_windows_console()
  
  # Capture packets in an infinite loop
  print("Starting packet capture. Press Ctrl+C to stop.")
  
  try:
    sniff(prn=packet_callback, store=0)
  except KeyboardInterrupt:
    print("Packet capture stopped.")
