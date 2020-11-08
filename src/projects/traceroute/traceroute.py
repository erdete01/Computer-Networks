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
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl))
    sock.sendto(pkt_bytes, (addr_dst, 33434))
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
    Returns properly formatted Echo request 
    """
    destination_reached = False
    ttl = 0
    dest_addr = socket.gethostbyname(hostname)
    print(f"\nTracing route to {hostname} [{dest_addr}]\n" + f"over a maximum of {max_hops} hops\n")
    req_id = os.getpid() & 0xFFFF
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")) as sock:
        while ttl < max_hops and not destination_reached:
            sock.settimeout(1)
            seq_id = 0
            comment = ''
            ttl += 1
            print(f"{ttl:>3d}   ", end="")
            for _ in range(ATTEMPTS):
                pkt_out = format_request(req_id, seq_id)
                # Send the request to the destination host
                time_sent = send_request(sock, pkt_out, dest_addr, ttl)
                # Receive an ICMP reply
                try:
                    pkt_in, resp_addr, time_rcvd = receive_reply(sock)
                except ValueError as val_err:
                    comment= (comment if comment else f"Error while parsing the response: {str(val_err)}")
                    print(f"{'!':>3s}      ", end="")
                    continue
                except (socket.timeout, TimeoutError) as to_err:
                    print(f"{'*':>3s}      ", end="")
                    comment = (comment if comment else f"Request timed out: {str(to_err)}")
                    continue
                seq_id += 1
                rtt = (time_rcvd - time_sent) * 1000
                if rtt > 1: 
                    try:
                        comment = (f"{socket.gethostbyaddr(resp_addr[0])[0]} [{resp_addr[0]}]")
                    except:
                        pass
                    print(f"{rtt:>3.0f} ms   ", end="")
                else:
                    print(f"{'<1':>3s} ms   ", end="")
                if not comment:
                    parse_reply(pkt_in)
                    comment = resp_addr[0] 
                if resp_addr[0] == dest_addr:
                    destination_reached = True
            print(comment)
    print("\nTrace complete.")

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
    traceroute(args.server)

#Main function
if __name__ == "__main__":
    main()
