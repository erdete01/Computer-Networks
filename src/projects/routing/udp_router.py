#!/usr/bin/env python3
"""Router implementation using UDP sockets"""

import argparse
import logging
import pathlib
import random
import select
import socket
import struct
import time
import toml
from typing import Tuple, Set, Dict
from socket import SOCK_DGRAM, AF_INET


THIS_HOST = None
BASE_PORT = 4300

def read_config_file(filename: str) -> Tuple[Set, Dict]:
    """
    Read config file

    :param filename: name of the configuration file
    :return tuple of the (neighbors, routing table)
    """
    try:
        myFile = open(filename, "r")
        myTuple = []
        myList = []
        for aline in myFile:
            values = aline.split()
            if len(values) != 0:
                myList.append(values)
            else:
                myTuple.append(myList)
                myList = []
        myTuple.append(myList)
        myneighbors = myTuple[0][1:]
        neighbors = []
        for i in myneighbors:
            neighbors.append(i[0])

        myrouting = {}
        print(myTuple[0][1:])
        for i in myneighbors:
            myrouting[i[0]] = [int(i[1]), i[0]]
        return (set(neighbors), myrouting)

    except:
        raise FileNotFoundError("Could not find the specified configuration file data/projects/routing/wrong_file.txt")
 

def format_update(routing_table: dict) -> bytes:
    """
    Format update message

    :param routing_table: routing table of this router
    :returns the formatted message
    """
    xs = bytearray()
    xs.append(0)
    for i in routing_table:
        xs += bytearray(socket.inet_aton(i))
        xs.append(routing_table[i][0])
    return bytes(xs)

def parse_update(msg: bytes, neigh_addr: str, routing_table: dict) -> bool:
    """
    Update routing table
    :param msg: message from a neighbor
    :param neigh_addr: neighbor's address
    :param routing_table: this router's routing table
    :returns True is the table has been updated, False otherwise
    """
    print(neigh_addr, routing_table)
    i = 1
    update = False
    while i < len(msg):
        preparringStruct = struct.unpack('!bbbbb', msg[i:i+5])
        # Get the IP value in String
        myIps = ""
        for val in preparringStruct:
            myIps += (str(val) + ".")
        myIps = (myIps[:-3])
        print(myIps)
        # Get the Cost from tuple
        myCost = preparringStruct[-1]

        if myIps in routing_table:
            # If the updated cost is less than the routing table cost, according to djikstra's algorithm
            # it should update the cost. Therefore, the smaller value should become the cost
            if routing_table[myIps][0] > myCost + routing_table[neigh_addr][0]:
                update = True
        i += 5
    return update  
    
def send_update(node: str) -> None:
    """
    Send update
    
    :param node: recipient of the update message
    """
    pass


def format_hello(msg_txt: str, src_node: str, dst_node: str) -> bytes:
    """
    Format hello message
    
    :param msg_txt: message text
    :param src_node: message originator
    :param dst_node: message recipient
    """
    xs = bytearray()
    xs.append(1)
    xs += bytearray(socket.inet_aton(src_node))
    xs += bytearray(socket.inet_aton(dst_node))
    a = bytearray(msg_txt.encode())
    byt_combined = xs + a
    return bytes(byt_combined)    


def parse_hello(msg: bytes, routing_table: dict) -> str:
    """
    Parse the HELLO message

    :param msg: message
    :param routing_table: this router's routing table
    :returns the action taken as a string
    """
    # Get the first two ips
    received = msg[1:5]
    receivedStruct = struct.unpack('!bbbb', received)

    sending = msg[5:9]
    sendingStruct = struct.unpack('!bbbb', sending)
    
    # Convert these two to one list
    finalList = []
    convertingToList = list(receivedStruct)
    converting2 = list(sendingStruct)
    finalList.append(convertingToList)
    finalList.append(converting2)
    
    # Preparring message
    myBytes = bytearray()
    message = msg[9:]
    lengthMessage = len(message)
    numberofB = int(lengthMessage) * "c"
    textStruct = struct.unpack('{}'.format(numberofB), message)
    for i in textStruct:
        myBytes.extend(i)
    myBytes = bytes(myBytes)

    # Preperraing to call the send_hello function
    src_node = ""
    for i in convertingToList:
        src_node += str(i)
        src_node += "."
    src_node = (src_node[:-1])

    dst_node = ""
    for i in converting2:
        dst_node += str(i)
        dst_node += "."
    dst_node = (dst_node[:-1])

    finalMessage = (myBytes.decode(), src_node, dst_node)
    if finalMessage[2] == '127.0.0.2':
        return f"Forwarded {finalMessage[0]} to {finalMessage[2]}"
    else:
        return f"Received {finalMessage[0]} from {finalMessage[1]}"


def send_hello(msg_txt: bytes, src_node: str, dst_node: str, routing_table: dict) -> None:
    """
    Send a message

    :param mst_txt: message to send
    :param src_node: message originator
    :param dst_node: message recipient
    :param routing_table: this router's routing table
    """            
    # Sending message Clients part
    with socket.socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(msg_txt, (dst_node, BASE_PORT))
        return (f"Forwarded {msg_txt.decode()} to {dst_node}")
        sock.close()
    # what_ready = select.select([my_socket], [], [])

def print_status(routing_table: dict) -> None:
    """
    Print status

    :param routing_table: this router's routing table
    """
    raise NotImplementedError


def route(neighbors: set, routing_table: dict, timeout: int = 5):
    """
    Router's main loop

    :param neighbors: this router's neighbors
    :param routing_table: this router's routing table
    :param timeout: default 5
    """
    ubuntu_release = [
        "Groovy Gorilla",
        "Focal Fossa",
        "Eoam Ermine",
        "Disco Dingo",
        "Cosmic Cuttlefish",
        "Bionic Beaver",
        "Artful Aardvark",
        "Zesty Zapus",
        "Yakkety Yak",
        "Xenial Xerus",
    ]
    raise NotImplementedError


def main():
    """Main function"""
    # Start with a socket application that reads 
    # network configuration from a file, binds to 
    # port 430**x**, and prints the routing table.
    with socket.socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(msg_txt, (dst_node, BASE_PORT))
        return (f"Forwarded {msg_txt.decode()} to {dst_node}")
        sock.close()
    # what_ready = select.select([my_socket], [], [])


if __name__ == "__main__":
    main()
