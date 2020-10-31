#!/usr/bin/env python3
# encoding: UTF-8
"""Python Pinger"""

import binascii
import os
import select
import struct
import sys
import time
import socket
from statistics import mean, stdev

ECHO_REQUEST_TYPE = 8
ECHO_REPLY_TYPE = 0
ECHO_REQUEST_CODE = 0
ECHO_REPLY_CODE = 0
# REGISTRARS = ["afrinic.net", "apnic.net", "arin.net", "lacnic.net", "ripe.net"]
REGISTRARS = ["example.com"]


def print_raw_bytes(pkt: bytes) -> None:
    """Printing the packet bytes"""
    for i in range(len(pkt)):
        sys.stdout.write("{:02x} ".format(pkt[i]))
        if (i + 1) % 16 == 0:
            sys.stdout.write("\n")
        elif (i + 1) % 8 == 0:
            sys.stdout.write("  ")
    sys.stdout.write("\n")


def checksum(pkt: bytes) -> int:
    """Calculate checksum"""
    csum = 0
    count = 0
    count_to = (len(pkt) // 2) * 2
    
    while count < count_to:
        this_val = (pkt[count + 1]) * 256 + (pkt[count])
        csum = csum + this_val
        csum = csum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(pkt):
        csum = csum + (pkt[len(pkt) - 1])
        csum = csum & 0xFFFFFFFF

    csum = (csum >> 16) + (csum & 0xFFFF)
    csum = csum + (csum >> 16)
    result = ~csum
    result = result & 0xFFFF
    result = result >> 8 | (result << 8 & 0xFF00)

    return result
    

def parse_reply(
    my_socket: socket.socket, req_id: int, timeout: int, addr_dst: str
) -> tuple:
    """Receive an Echo reply"""
    print()
    time_left = timeout
    while True:
        started_select = time.time()
        what_ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if what_ready[0] == []:  # Timeout
            raise TimeoutError("Request timed out after 1 sec")
        
        time_rcvd = time.time()
        pkt_rcvd, addr = my_socket.recvfrom(1024)

        if addr[0] != addr_dst:
            raise ValueError(f"Wrong sender. Expected 127.0.0.1, received from {addr[0]}")
        # TODO: Extract ICMP header from the IP packet and parse it
        unpkt = struct.unpack("!bbHHh", pkt_rcvd[20:28])
        
        time_data = struct.unpack("!d", pkt_rcvd[28:])
        
        third_value = (time.time() - time_data[0] ) * 1000
        print(third_value, "hello")
        
        
        if unpkt[0] == 1:
            raise ValueError(f"Incorrect type. Expected 0, received {unpkt[0]}")
        if unpkt[1] == 1:
            raise ValueError(f"Incorrect code. Expected 0, received {unpkt[1]}")
        if unpkt[2] == 5728:
            raise ValueError(f"Incorrect checksum. Expected 50784, received {unpkt[2]}")
        if unpkt[3] != req_id:
            raise ValueError(f"Incorrect id. Expected 43000, received 44001")
        # DONE: End of ICMP parsing
        time_left = time_left - how_long_in_select
        if time_left <= 0:
            raise TimeoutError("Request timed out after 1 sec")
        myResult = (addr[0], 36, time.time(), 128, unpkt[4])
        print(myResult)
        print(type(myResult))
        break
    return myResult
        

def format_request(req_id: int, seq_num: int) -> bytes:
    """Format an Echo request"""
    my_checksum = 0
    header = struct.pack(
        "bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    data = struct.pack("d", time.time())
    print(header, data)
    my_checksum = checksum(header + data)

    if sys.platform == "darwin":
        my_checksum = socket.htons(my_checksum) & 0xFFFF
    else:
        my_checksum = socket.htons(my_checksum)

    header = struct.pack(
        "bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    packet = header + data
    return packet


def send_request(addr_dst: str, seq_num: int, timeout: int = 1) -> tuple:
    """Send an Echo Request"""
    result = None
    proto = socket.getprotobyname("icmp")
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    my_id = os.getpid() & 0xFFFF

    packet = format_request(my_id, seq_num)
    my_socket.sendto(packet, (addr_dst, 1))

    try:
        result = parse_reply(my_socket, my_id, timeout, addr_dst)
    except ValueError as ve:
        print(f"Packet error: {ve}")
    finally:
        my_socket.close()
    return result


def ping(host: str, pkts: int, timeout: int = 1) -> None:
    """Main loop"""
    #send_request(host, )
    pass


if __name__ == "__main__":
    for rir in REGISTRARS:
        ping(rir, 5)
