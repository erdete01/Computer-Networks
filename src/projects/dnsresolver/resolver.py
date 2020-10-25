#!/usr/bin/env python3
"""
DNS Resolver
"""

import argparse
import logging
from random import randint, choice
from re import match
from socket import TCP_LINGER2, socket, SOCK_DGRAM, AF_INET
from typing import Tuple, List
import random
import re

PORT = 53

DNS_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "PTR": 12, "TXT": 16}

PUBLIC_DNS_SERVER = [
    "1.0.0.1",  # Cloudflare
    "1.1.1.1",  # Cloudflare
    "8.8.4.4",  # Google
    "8.8.8.8",  # Google
    "8.26.56.26",  # Comodo
    "8.20.247.20",  # Comodo
    "9.9.9.9",  # Quad9
    "64.6.64.6",  # Verisign
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
]


def val_to_2_bytes(value: int) -> Tuple[int]:
    """
    Split a value into 2 bytes
    Return the result as a tuple of 2 integers
    """
    left_value = value >> 8
    right_value = value & 0xFF
    return left_value, (right_value)


def val_to_n_bytes(value: int, n_bytes: int) -> Tuple[int]:
    """
    Split a value into n bytes
    Return the result as a tuple of n integers
    """
    myList = []
    myValue = value
    i = 1
    while i < n_bytes:
        myList.append(value >> i * 8 & 0xFF)
        i += 1
    myList = myList[::-1]
    myList.append(myValue & 0xFF)
    return (tuple(myList))
    

def bytes_to_val(byte_list: list) -> int:
    """Merge n bytes into a value"""
    i = 0
    myNumber = byte_list[0]
    while i < len(byte_list)-1:
        myNumber = myNumber << 8
        myNumber = myNumber | byte_list[i+1] 
        i += 1
    return myNumber
    


def get_2_bits(byte_list: list) -> int:
    """
    Extract first two bits of a two-byte sequence
    Return the result as a decimal value
    """
    a = hex( ((byte_list[0]<<10) | byte_list[1]) )
    res = int(a, 16) 
    return (res >> 16)
    

def get_domain_name_location(byte_list: list) -> int:
    """
    Extract size of the offset from a two-byte sequence
    Return the result as a decimal value
    """
    mergedValue = bytes_to_val(byte_list) 
    mergedValue = (mergedValue & 0xFF)
    return mergedValue


def parse_cli_query(
    q_domain: str, q_type: str, q_server: str = None
) -> Tuple[list, int, str]:
    if q_type == "AAAA" or q_type == "A":
        q_domainList = q_domain.split(".")
        q_type_number = DNS_TYPES[q_type]
        if q_server == None:
            q_server = random.choice(PUBLIC_DNS_SERVER)
        return (((q_domainList, q_type_number, q_server)))
    if q_type == "MX" or q_type == "AAA":
        raise ValueError("Unknown query type")

def format_query(q_domain: list, q_type: int) -> bytearray:
    """
    Format DNS query
    Take the domain name (as a list) and the record type as parameters
    Return a properly formatted query
    Assumpions (defaults):
    - transaction id: random 0..65535
    - flags: recursive query set
    - questions: 1
    - class: Internet
    """
    num = randint(0, 65535)
    flags = 0x100
    q = 1
    ans = 0
    aut = 0
    add = 0
    q_class = 1

    byte_arr = bytearray()
    byte_arr.extend(val_to_2_bytes(num))
    byte_arr.extend(val_to_2_bytes(flags))
    byte_arr.extend(val_to_2_bytes(q))
    byte_arr.extend(val_to_2_bytes(ans))
    byte_arr.extend(val_to_2_bytes(aut))
    byte_arr.extend(val_to_2_bytes(add))

    for i in q_domain:
        byte_arr.append(len(i))
        for aChar in i:
            byte_arr.append(ord(aChar))

    byte_arr.extend(b'\00')
    byte_arr.extend(val_to_2_bytes(q_type))
    byte_arr.extend(val_to_2_bytes(q_class))
    return(byte_arr)

def parse_response(resp_bytes: bytes) -> list:
    """
    Parse server response
    Take response bytes as a parameter
    Return a list of tuples in the format of (name, address, ttl)
    """
    # b'\xc7D\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00
    # \x06luther\x03edu\x00\x00\x01\x00\x01\xc0\x0c\
    # x00\x01\x00\x01\x00\x00\x01,\x00\x04\xae\x81\x19\xaa'
    myTuple = []
    answer_start = resp_bytes[12]
    answer_start2 = resp_bytes[25]
    answer_start3 = answer_start + answer_start2 + 1
    rr_ans = resp_bytes[7]
    print(resp_bytes.decode("utf-8"), "Does it work?")
    print(answer_start, "TEST2",answer_start2, "TEST", answer_start3)
    print(resp_bytes)

    for i in range(rr_ans):
        answer = parse_answers(resp_bytes, 12, rr_ans)
        myTuple.append(answer)
        
    # print(parse_answers(resp_bytes, answer_start, rr_ans))

def parse_answers(resp_bytes: bytes, answer_start: int, rr_ans: int) -> List[tuple]:
    """
    Parse DNS server answers
    Take response bytes, offset, and the number of answers as parameters
    Return a list of tuples in the format of (name, address, ttl)
    """
    domain_name = ''
    for i in range(13, 13 + resp_bytes[12]):
        domain_name += (chr(resp_bytes[i]))
    domain_name = domain_name + "."
    for i in range(18, 18 + resp_bytes[12]):
        domain_name += (chr(resp_bytes[i]))

    if answer_start >= 28:
        myBytes = resp_bytes[answer_start+12:answer_start+17]
        ipAdd = parse_address_a(4, myBytes)
        print(ipAdd, "This is 4")
    else:
        test_str = str(resp_bytes)
        test_sub = "x01I"
        matches = re.finditer(test_sub, test_str)
        matches_positions = [match.start() for match in matches]
        print(matches_positions, "Hello I am Groot")
        for i in matches_positions:
            print(resp_bytes[i+12:i+28])
        # resp_bytes.find(b'\x01I\x98')
        # print(resp_bytes)

            # myIndex = pass
            # myBytes = resp_bytes[answer_start+12:answer_start+28]
            # ipAdd = parse_address_aaaa(16, myBytes)
            # print(ipAdd,"this is 16")

    # ipAdd = []
    # for i in range(rr_ans):
    #     ipAdd.append(resp_bytes[answer_start+12:answer_start+16])

    # myIPAddress = list(resp_bytes[answer_start+12:answer_start+16])
    
    return ()
    # print(resp_bytes, "   number 1   ", answer_start, "   number 2   ", rr_ans, "I am here")


def parse_address_a(addr_len: int, addr_bytes: bytes) -> str:
    """
    Parse IPv4 address
    Convert bytes to human-readable dotted-decimal
    """
    myStr = ""
    for i in  list(addr_bytes):
        myStr += (str(i) + '.')
    return myStr[:-1]
    

def parse_address_aaaa(addr_len: int, addr_bytes: bytes) -> str:
    """Extract IPv6 address"""
    # TODO: Implement this function
    myStr = ""
    myList = list(addr_bytes)

    i = 0
    j = 1

    while i < len(myList) and j < len(myList):
        
        firstNumber = myList[i] << 8
        secondNumber = hex(myList[j] | firstNumber)
        myStr += (secondNumber[2:] + ":")
        print(myStr)

        i += 2
        j += 2

    return myStr[:-1]

def resolve(query: tuple) -> None:
    """Resolve the query"""
    try:
        q_domain, q_type, q_server = parse_cli_query(*query)
    except ValueError as ve:
        print(ve.args[0])
        exit()
    logging.info(f"Resolving type {q_type} for {q_domain} using {q_server}")
    query_bytes = format_query(q_domain, q_type)
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(query_bytes, (q_server, PORT))
        response_data, _ = sock.recvfrom(2048)
    answers = parse_response(response_data)
    print(f"DNS server used: {q_server}")
    for a in answers:
        print()
        print(f"{'Domain:':10s}{a[0]}")
        print(f"{'Address:':10s}{a[1]}")
        print(f"{'TTL:':10s}{a[2]}")


def main():
    """Main function"""
    # TODO: Complete this function
    arg_parser = argparse.ArgumentParser(description="Parse arguments")

    arg_parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable logging.DEBUG mode"
    )

    args = arg_parser.parse_args()
    
    arg_parser.add_argument(
        "domain", type=str, nargs="+", help="domain"
    )

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)

    resolve((args.domain, args.type, args.server))
    # raise NotImplementedError


if __name__ == "__main__":
    main()
