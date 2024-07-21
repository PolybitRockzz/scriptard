import socket
import struct
import textwrap

def ethernet_frame(data):
  dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
  return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]

def get_mac_addr(bytes_addr):
  bytes_str = map('{:02x}'.format, bytes_addr)
  mac_addr = ':'.join(bytes_str).upper()
  return mac_addr

def match_main_protocol(proto):
  match proto:
    case 8:
      return 'IPv4'
    case _:
      return 'Unknown'

def match_protocol(proto):
  match proto:
    case 1:
      return 'ICMP'
    case 2:
      return 'IGMP'
    case 6:
      return 'TCP'
    case 9:
      return 'IGRP'
    case 17:
      return 'UDP'
    case 47:
      return 'GRE'
    case 50:
      return 'ESP'
    case 51:
      return 'AH'
    case 57:
      return 'SKIP'
    case 88:
      return 'EIGRP'
    case 89:
      return 'OSPF'
    case 115:
      return 'L2TP'
    case _:
      return 'Unknown'

def ipv4_packet(data):
  version_header_length = data[0]
  version = version_header_length >> 4
  header_length = (version_header_length & 15) * 4
  ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
  return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
  addr_str = '.'.join(map(str, addr))
  return addr_str

def icmp_packet(data):
  icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
  return icmp_type, code, checksum, data[4:]

def tcp_packet(data):
  (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
  offset = (offset_reserved_flags >> 12) * 4
  flag_urg = (offset_reserved_flags & 32) >> 5
  flag_ack = (offset_reserved_flags & 16) >> 4
  flag_psh = (offset_reserved_flags & 8) >> 3
  flag_rst = (offset_reserved_flags & 4) >> 2
  flag_syn = (offset_reserved_flags & 2) >> 1
  flag_fin = offset_reserved_flags & 1
  return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
  src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
  return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=50):
  size -= len(prefix)
  if isinstance(string, bytes):
    string = '.'.join(r'\x{:02x}'.format(byte) for byte in string)
    if size % 2:
      size -= 1
  return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
  HOST = socket.gethostbyname(socket.gethostname())
  conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
  conn.bind((HOST, 0))
  conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
  conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
  
  while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print(f'(Src) {src_mac} -> {dest_mac} (Dest), Protocol: {match_main_protocol(eth_proto)} [{eth_proto}]')
    
    if match_main_protocol(eth_proto) == 'IPv4':
      (version, header_length, ttl, proto, src, target, ipv4_data) = ipv4_packet(data)
      print(f'  Version: {version}, Header Length: {header_length}, TTL: {ttl}')
      print(f'  Protocol: {match_protocol(proto)} [{proto}], Source: {src}, Target: {target}')
      
      if match_protocol(proto) == 'ICMP':
        icmp_type, code, checksum, icmp_data = icmp_packet(ipv4_data)
        print(f'    Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
        print('    Payload Data:')
        print(format_multi_line('      ', icmp_data))
        
      elif match_protocol(proto) == 'TCP':
        src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = icmp_packet(ipv4_data)
        print(f'    Source Port: {src_port}, Destination Port: {dest_port}')
        print(f'    Sequence: {sequence}, Acknowledgement: {acknowledgement}')
        print('    Flags:')
        print(f'      URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
        print('    Payload Data:')
        print(format_multi_line('      ', tcp_data))
        
      elif match_protocol(proto) == 'UDP':
        src_port, dest_port, size, udp_data = icmp_packet(ipv4_data)
        print(f'    Source Port: {src_port}, Destination Port: {dest_port}, Size: {size}')
        print('    Payload Data:')
        print(format_multi_line('      ', udp_data))
  
if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print("Process Interrupted using Keyboard.")