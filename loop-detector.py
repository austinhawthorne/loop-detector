#!/usr/bin/env python3
"""
Continuous IPv4 Broadcast Loop Detector (Detect Only Looped Packets)

This script continuously sends out IPv4 broadcast packets with a unique run identifier
and an incrementing sequence number in the payload on the specified interface.
It records the time each packet is sent and then listens for incoming packets.
When a packet with the same run identifier is received, the script checks the time
difference between when it was sent and when it was received. If the delay is greater
than a threshold (indicating that the packet has traversed the network and looped back),
it prints a loop detection message.

Usage:
  sudo ./continuous_ipv4_loop_detector.py -i <interface> -s <send_interval> -d <delay_threshold>

Arguments:
  -i, --interface     Network interface to use (e.g., eth0)
  -s, --send_interval Interval in seconds between sending broadcast packets (default: 1 second)
  -d, --delay_threshold Minimum delay (in seconds) to consider a packet looped back (default: 0.1 seconds)
"""

import argparse
import threading
import time
import uuid
from scapy.all import Ether, IP, UDP, Raw, sendp, sniff, get_if_hwaddr, get_if_addr

# Global run identifier (unique for this execution)
RUN_ID = uuid.uuid4().hex

# Global counter for sequence numbers and a dictionary to record send times
seq_counter = 1
send_times = {}  # { sequence_number: send_time }
lock = threading.Lock()

def create_payload(seq):
    """
    Create a payload that includes the run ID and sequence number.
    Format: "<RUN_ID>:<sequence>"
    """
    return f"{RUN_ID}:{seq}".encode()

def send_broadcast_ipv4(interface, payload, seq):
    """
    Craft and send an IPv4 broadcast packet with the provided payload.
    Records the send time for the given sequence number.
    """
    src_mac = get_if_hwaddr(interface)
    src_ip = get_if_addr(interface)
    pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
           IP(src=src_ip, dst="255.255.255.255") /
           UDP(sport=54321, dport=54321) /
           Raw(load=payload))
    sendp(pkt, iface=interface, verbose=False)
    with lock:
        send_times[seq] = time.time()

def continuous_sender(interface, interval):
    """
    Continuously send broadcast packets on the given interface at the specified interval.
    Each packet carries an incrementing sequence number.
    """
    global seq_counter
    print(f"[Sender] Starting continuous broadcast every {interval} seconds.")
    while True:
        with lock:
            current_seq = seq_counter
            seq_counter += 1
        payload = create_payload(current_seq)
        send_broadcast_ipv4(interface, payload, current_seq)
        print(f"[Sender] Sent packet with sequence {current_seq}")
        time.sleep(interval)

def packet_handler(pkt, delay_threshold):
    """
    Callback for sniffed packets.
    Looks for IPv4 broadcast packets containing our unique run ID.
    If a packet's arrival time is delayed beyond the threshold from its send time,
    it's considered a looped packet.
    """
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw):
        # Only consider packets sent to the broadcast IP address.
        if pkt[IP].dst != "255.255.255.255":
            return
        try:
            payload_str = pkt[Raw].load.decode()
            run_id, seq_str = payload_str.split(":", 1)
            seq = int(seq_str)
        except Exception:
            return  # Payload doesn't match our expected format

        # Check that this packet is from our current run.
        if run_id != RUN_ID:
            return

        with lock:
            send_time = send_times.get(seq)
        if send_time is None:
            # We don't have a record for this sequence; ignore it.
            return

        delay = time.time() - send_time
        if delay > delay_threshold:
            print(f"[Sniffer] Loop detected: Packet with sequence {seq} arrived after {delay:.3f} seconds (threshold {delay_threshold}s)")
        # Else, it's the local transmit copy, so ignore it.

def continuous_sniffer(interface, delay_threshold):
    """
    Continuously sniff on the specified interface and process packets with packet_handler.
    The handler is provided the delay threshold to decide if a packet is looped.
    """
    print(f"[Sniffer] Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, delay_threshold), store=0)

def main():
    parser = argparse.ArgumentParser(
        description="Continuously send IPv4 broadcast packets and detect only looped (reflected) packets."
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0)")
    parser.add_argument("-s", "--send_interval", type=float, default=1.0,
                        help="Interval in seconds between sending broadcast packets (default: 1)")
    parser.add_argument("-d", "--delay_threshold", type=float, default=0.1,
                        help="Minimum delay (in seconds) to consider a packet looped back (default: 0.1)")
    args = parser.parse_args()

    print("Run ID (unique for this execution):", RUN_ID)

    # Start sender and sniffer threads.
    sender_thread = threading.Thread(target=continuous_sender, args=(args.interface, args.send_interval))
    sniffer_thread = threading.Thread(target=continuous_sniffer, args=(args.interface, args.delay_threshold))

    sender_thread.daemon = True
    sniffer_thread.daemon = True

    sender_thread.start()
    sniffer_thread.start()

    print("Continuous broadcast and loop detection are running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    main()
