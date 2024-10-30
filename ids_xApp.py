import time
import os
import sys
import signal
from collections import deque, defaultdict
import subprocess  # Use subprocess instead of os.popen for better real-time capture
from tabulate import tabulate
import logging
import threading
from scapy.all import ARP, sniff


# Dictionary to track IP-to-MAC mappings
ip_mac_map = defaultdict(set)
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(message)s")

cur_dir = os.path.dirname(os.path.abspath(__file__))
sdk_path = cur_dir + "/../xapp_sdk/"
sys.path.append(sdk_path)

import xapp_sdk as ric  # Assuming xapp_sdk is correctly configured

# Threshold for SYN flood detection
last_flood_log_time = 0  # Track last log time to avoid repetitive logging
FLOOD_LOG_INTERVAL = 5  # Log flood detection once every 5 seconds
SYN_FLOOD_THRESHOLD = 1000  # Adjust this based on your network traffic patterns
MONITOR_INTERVAL = 10  # Monitor every 5 seconds
process = None
#print(dir(ric))

# Deque to store timestamps of SYN packets
syn_packet_timestamps = deque()

# FlexRIC node handlers (global)
mac_hndlr = {}
rlc_hndlr = {}
pdcp_hndlr = {}
kpm_hndlr = {}

# Function to generate ID key based on node information
def gen_id_key(id):
    plmn = "PLMN_" + str(id.plmn.mcc) + str(id.plmn.mnc)
    nb_id = "NBID_" + str(id.nb_id.nb_id)
    ran_type = get_ngran_name(id.type)
    return plmn + "-" + nb_id + "-" + ran_type


# Function to send alarm to FlexRIC
def send_alarm_to_flexric():
    e2_nodes = ric.conn_e2_nodes()
    if not e2_nodes:
        print("No E2 node connected to send alarm.")
        return

    for node in e2_nodes:
        print(f"Sending SYN Flood Alarm to FlexRIC for node {node.id.nb_id.nb_id}")
        # Send an alarm to FlexRIC using the SDK
        alarm_message = f"SYN Flood detected on node {node.id.nb_id.nb_id}."
        ric.send_custom_alarm(node.id, alarm_message)  # Replace with actual alarm function from FlexRIC SDK

# Function to detect SYN flood based on packet timestamps
#def detect_syn_flood():
#    current_time = time.time()

    # Remove timestamps older than MONITOR_INTERVAL seconds
#    while syn_packet_timestamps and current_time - syn_packet_timestamps[0] > MONITOR_INTERVAL:
#        syn_packet_timestamps.popleft()

#    syn_count = len(syn_packet_timestamps)
#    if syn_count > SYN_FLOOD_THRESHOLD:
#        logging.warning(f"SYN Flood Detected - {syn_count} SYN packets in the last {MONITOR_INTERVAL} seconds.")
        #send_alarm_to_flexric()  # Send alarm if threshold is breached
def detect_syn_flood():
    global last_flood_log_time
    current_time = time.time()

    # Clear timestamps older than the monitoring interval
    while syn_packet_timestamps and current_time - syn_packet_timestamps[0] > MONITOR_INTERVAL:
        syn_packet_timestamps.popleft()

    syn_count = len(syn_packet_timestamps)

    # Log flood detection only if threshold is crossed and enough time has passed
    if syn_count > SYN_FLOOD_THRESHOLD:
        if current_time - last_flood_log_time >= FLOOD_LOG_INTERVAL:
            # Calculate the time elapsed within the current monitor interval
            elapsed_interval = MONITOR_INTERVAL if MONITOR_INTERVAL > 0 else 1
            logging.warning(f"SYN Flood Detected - {syn_count} SYN packets in the last {elapsed_interval} seconds.")
            #send_alarm_to_flexric()  # Send alarm when threshold is breached
            last_flood_log_time = current_time  # Update last log time


def detect_ip_spoofing():
    def process_arp_packet(packet):
        if ARP in packet:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            # Add the MAC to the set of known MACs for this IP
            ip_mac_map[ip].add(mac)
            logging.debug(f"ARP packet detected: IP={ip}, MAC={mac}")
            logging.debug(f"Current IP-to-MAC mappings: {dict(ip_mac_map)}")

            # Check if there are multiple MAC addresses for a single IP
            if len(ip_mac_map[ip]) > 1:
                logging.warning(f"IP Spoofing Detected - Multiple MACs for IP {ip}: {ip_mac_map[ip]}")

    logging.info("Starting Enhanced IP Spoofing Detection...")

    # Start sniffing for ARP packets, capturing both requests and replies
    sniff(filter="arp", prn=process_arp_packet, iface="eth0", store=0)

# Function to capture SYN packets using tcpdump
def capture_syn_packets():
    interface = "eth0"  # Modify to match your network interface
    command = ["sudo", "tcpdump", "-i", interface, "-n", "-c", "15000", "tcp[tcpflags] & (tcp-syn) != 0"]

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    for line in process.stdout:
        if "Flags [S]" in line:
            # Add timestamp for each SYN packet detected without printing
            syn_packet_timestamps.append(time.time())
        detect_syn_flood()  # Check for SYN flood conditions

    process.wait()  # Wait for tcpdump process to finish


# Signal handler to clean up on Ctrl-C
def sig_handler(signum, frame):
    print("Ctrl-C Detected. Exiting.")
    if process:
        process.terminate()  # Terminate tcpdump process
    sys.exit(0)  # Exit the program


def print_e2_nodes():
    """
    print_e2_nodes():
        Print connected E2-Nodes' stats in a table.
    """
    e2nodes_data = []
    conn = ric.conn_e2_nodes()
    for i in range(len(conn)):
        info = [conn[i].id.nb_id.nb_id, conn[i].id.plmn.mcc, conn[i].id.plmn.mnc, get_ngran_name(conn[i].id.type)]
        e2nodes_data.append(info)
    print(tabulate(e2nodes_data, headers=["nb_id", "mcc", "mnc", "ran_type"], tablefmt="grid"))

def get_ngran_name(ran_type):
    if ran_type == 0:
        return "ngran_eNB"
    elif ran_type == 2:
        return "ngran_gNB"
    elif ran_type == 5:
        return "ngran_gNB_CU"
    elif ran_type == 7:
        return "ngran_gNB_DU"
    else:
        return "Unknown"

def send_subscription_req(node, cust_sm, oran_sm):
    """
    Send subscription requests to the E2 node.
    Parameters:
        node: E2 node to send the subscription to
        cust_sm: Custom service models
        oran_sm: ORAN service models
    """
    for sm_info in cust_sm:
        sm_name = sm_info.name
        sm_time = sm_info.time
        tti = get_cust_tti(sm_time)

        if sm_name == "MAC" and (node.id.type == ric.e2ap_ngran_gNB or node.id.type == ric.e2ap_ngran_gNB_DU or node.id.type == ric.e2ap_ngran_eNB):
            print(f"<<<< Subscribe to {sm_name} with time period {sm_time} >>>>")
            send_mac_sub_req(node.id, tti)
        elif sm_name == "RLC" and (node.id.type == ric.e2ap_ngran_gNB or node.id.type == ric.e2ap_ngran_gNB_DU or node.id.type == ric.e2ap_ngran_eNB):
            print(f"<<<< Subscribe to {sm_name} with time period {sm_time} >>>>")
            send_rlc_sub_req(node.id, tti)
        elif sm_name == "PDCP" and (node.id.type == ric.e2ap_ngran_gNB or node.id.type == ric.e2ap_ngran_gNB_CU or node.id.type == ric.e2ap_ngran_eNB):
            print(f"<<<< Subscribe to {sm_name} with time period {sm_time} >>>>")
            send_pdcp_sub_req(node.id, tti)
        else:
            print(f"Not yet implemented function to send subscription for {sm_name}")

    for sm_info in oran_sm:
        sm_name = sm_info.name
        if sm_name != "KPM":
            print(f"Not supporting {sm_name} in Python")
            continue
        sm_time = sm_info.time
        tti = get_oran_tti(sm_time)
        act = [a.name for a in sm_info.actions]
        send_kpm_sub_req(node.id, tti, act)

def run_syn_flood_detection():
    while True:
        capture_syn_packets()
        time.sleep(MONITOR_INTERVAL)

# Function to run IP spoofing detection continuously
def run_ip_spoofing_detection():
    while True:
        detect_ip_spoofing()
        time.sleep(MONITOR_INTERVAL)


# Main loop to capture SYN packets and monitor for floods
def main():
    signal.signal(signal.SIGINT, sig_handler)

    print("Starting SYN Flood Detection and IP Spoofing")

    # Continuous monitoring loop
    #while True:
    #    capture_syn_packets()
    #    detect_ip_spoofing()
    #    time.sleep(MONITOR_INTERVAL)

    # Start SYN flood detection in a separate thread
    syn_thread = threading.Thread(target=run_syn_flood_detection, daemon=True)
    syn_thread.start()

    # Start IP spoofing detection in a separate thread
    spoofing_thread = threading.Thread(target=run_ip_spoofing_detection, daemon=True)
    spoofing_thread.start()

    # Keep main thread alive to handle signals
    syn_thread.join()
    spoofing_thread.join()


####################
#### MAIN SETUP FOR FLEXRIC
####################
ric.init(sys.argv)
cust_sm = ric.get_cust_sm_conf()
oran_sm = ric.get_oran_sm_conf()

signal.signal(signal.SIGINT, sig_handler)

e2nodes = ric.conn_e2_nodes()

while not e2nodes:
    print("No E2 node connects")
    time.sleep(1)
    e2nodes = ric.conn_e2_nodes()

print_e2_nodes()

for node in e2nodes:
    send_subscription_req(node, cust_sm, oran_sm)
    time.sleep(1)

# Start the SYN flood detection process
main()
