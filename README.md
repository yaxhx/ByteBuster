
# ByteBuster

This Python script is a basic packet sniffer designed to capture HTTP requests and extract potential login information from network packets. It also provides some utility functions for network interface details like MAC and IP addresses. The script uses various libraries such as psutil, subprocess, scapy, and prettytable to accomplish these tasks.
## Features

- Capture and Inspect Network Packets: Sniffs network traffic to capture HTTP requests.
- Extract Login Information: Identifies potential usernames and passwords from HTTP requests.
- Network Interface Details: Displays the MAC address and IP address of network interfaces.
- Raw Packet Output: Optionally prints raw HTTP packet details.

## Installation

- Clone the repo
```
git clone https://github.com/yaxhx/ByteBuster.git
```
- Install the libraries
```
pip install -r req.txt
```

## Usage

Run the Script:

Execute the script with administrative privileges to allow packet sniffing:

```bash
sudo python3 packet_sniffer.py
```

Enter Interface Name:

When prompted, enter the name of the network interface you want to monitor (e.g., eth0, wlan0).

Choose to Print Raw Packets:

You will be asked if you want to print raw HTTP packets. Enter Y for Yes or N for No.

View Output:

The script will display a table of network interfaces with their IP and MAC addresses, and then it will begin sniffing packets. If HTTP requests are detected, potential login information will be displayed.

Stop the Sniffer:

You can stop the packet sniffing process by pressing Ctrl+C.
