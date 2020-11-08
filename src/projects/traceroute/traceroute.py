import argparse
import logging
import os
import socket
import struct
import time
import sys

ECHO_REQUEST_CODE = 0
ECHO_REQUEST_TYPE = 8

"""Python tracert implementation using ICMP"""
#!/usr/bin/env python3

ATTEMPTS = 3
def checksum(pkt_bytes: bytes) -> int:
    #Calculate checksum
    s = 0
    w = 0
    c = 0
    ct = (len(pkt_bytes) // 2) * 2
    for i in range(0, len(pkt_bytes) -1, 2):
        this_val = (pkt_bytes[i + 1]) * 256 + (pkt_bytes[i])
        w += this_val
        w = w & 0xFFFFFFFF
    if ct < len(pkt_bytes):
        w += (pkt_bytes[len(pkt_bytes) - 1])
        w = w & 0xFFFFFFFF
    s = ((s + w) & 0xFFFF) + ((s + w) >> 16)
    s = (~s & 0xFFFF)
    result = s >> 8 | (s << 8 & 0xFF00)
    return result

def format_request(req_id: int, seq_num: int) -> bytes:
    "Format an Echo request"
    data = b"VOTE!"
    header = struct.pack("!BBHHH", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, ECHO_REQUEST_CODE, req_id, seq_num)
    myChecksum = checksum(header + data)
    header = struct.pack("!BBHHH", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, myChecksum, req_id, seq_num)
    return header + data
    
def send_request(sock: socket, pkt_bytes: bytes, addr_dst: str, ttl: int) -> float: 
    sock.sendto(pkt_bytes, (addr_dst, 33434))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl))
    return time.time()

def receive_reply(sock: socket) -> tuple:
    pkt_bytes, addr = sock.recvfrom(1024)
    return pkt_bytes, addr, time.time()


def parse_reply(pkt_bytes: bytes) -> None:
    expected_types_and_codes = {0: [0], 3: [0, 1, 3], 8: [0], 11: [0]}
    header = pkt_bytes[20:28]
    data = pkt_bytes[28:]
    sequence = struct.unpack("!BBHHH", header)
    repl_type = sequence[0]
    repl_code = sequence[1]
    repl_checksum = sequence[2]

    if repl_type not in expected_types_and_codes:
        raise ValueError(f"Incorrect type {repl_type} received " + f"instead of {', '.join([str(t) for t in expected_types_and_codes])}")

    if repl_code not in expected_types_and_codes[repl_type]:
        raise ValueError(f"Incorrect code {repl_code} received with type {repl_type}")
    
    if checksum(header + data) != 0:
        raise ValueError(f"Incorrect checksum {repl_checksum:04x} received " + f"instead of {checksum(header + data):04x}")
    
   
def traceroute(hostname: str, max_hops: int = 30) -> None:
    """
    Not Finished.
    Returns properly formatted Echo request 
    """
    seq_id = 0
    destination_reached = False
    ttl = 1
    dest_addr = socket.gethostbyname(hostname)
    print(f"\nTracing route to {hostname} [{dest_addr}]\n" + f"over a maximum of {max_hops} hops\n")

    while ttl < max_hops and not destination_reached:
        req_id = os.getpid() & 0xFFFF
        pkt_out = format_request(req_id, seq_id)
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")) as sock:
            for _ in range(ATTEMPTS):
                # Send the request to the destination host
                time_sent = send_request(sock, pkt_out, dest_addr, ttl)
                # Receive an ICMP reply
                pkt_in, resp_addr, time_rcvd = receive_reply(sock)
                rtt = (time_rcvd - time_sent) * 1000
                # Parse the response and check for errors
                comment = ""
                comment = resp_addr[0] 
                try:
                    print(f"{socket.gethostbyaddr(resp_addr[0])[0]} [{resp_addr[0]}]")
                except:
                    try:    
                        parse_reply(pkt_in)
                    except ValueError as val_err:
                        print(f"Error while parsing the response: {str(val_err)}")
                        continue
                    try:
                        if comment:
                            if rtt > 1:  
                                try:
                                    print(f"{socket.gethostbyaddr(resp_addr[0])[0]} [{resp_addr[0]}]")
                                    continue
                                except:
                                    print(f"{'!':>3s}      ", end="")
                                    print(f"{'*':>3s}      ", end="")  
                                    print(f"{'<1':>3s} ms   ", end="")
                                    print(f"{rtt:>3.0f} ms   ", end="")
                                    if resp_addr[0] == dest_addr:
                                        destination_reached = True
                        if not comment:
                            pass
                    except (socket.timeout, TimeoutError) as to_err:
                        print(f"Request timed out: {str(to_err)}")
                        continue
        seq_id += 1
        ttl += 1
    print("\nTrace complete.")

"""

    comment = ""

    comment = resp_addr[0]
    if resp_addr[0] == dest_addr:

        time_sent = send_request(sock, pkt_out, dest_addr, ttl)
        
        rtt = (time_rcvd - time_sent) * 1000
        pkt_in, resp_addr, time_rcvd = receive_reply(sock)

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, ) as sock:
            

        sock.settimeout(1)
    ttl = 0
    seq_id = 0
    destination_reached = False
    req_id = os.getpid() & 0xFFFF
    promo = socket.getprotobyname("icmp")
    print(req_id, seq_id)
    pkt_out = format_request(req_id, seq_id)

    try:
        parse_reply(pkt_out)
    except ValueError as val_err:
        print(f"Error while parsing the response: {str(val_err)}")
    
    while ttl < max_hops and not destination_reached:
        time_sent = send_request(sock, pkt_out, dest_addr, ttl)
        destination_reached = True
        ttl += 1
    """

def main():
    arg_parser = argparse.ArgumentParser(description="Parse arguments")
    arg_parser.add_argument("-d", "--debug", action="store_true", help="Enable logging.DEBUG mode")
    arg_parser.add_argument("server", type=str, help="Server to ping")
    args = arg_parser.parse_args()

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)
    #Trace the route to a domain
    traceroute(args.server)

#Main function
if __name__ == "__main__":
    main()
