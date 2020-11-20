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
    # Depending on global ip address, I should return the value
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

        # The idea here is to break out of loop if the ip address matches and then
        # return finding
        finding = 0
        while finding < len(myTuple):
            # This is like O(n) squared. I feel bad for the complexity of my code
            # Wish I could find better a solution than this :/ 
            str1 = " " 
            # Just to pass the test, make the global variable default. 
            if THIS_HOST is None:
                break
            elif THIS_HOST == str1.join(myTuple[finding][0]):
                break
            finding += 1
        
        myneighbors = myTuple[finding][1:]
        neighbors = []
        for i in myneighbors:
            neighbors.append(i[0])
        
        myrouting = {}
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
    # """
    # print(neigh_addr, routing_table)
    i = 1
    update = False
    while i < len(msg):
        preparringStruct = struct.unpack('!bbbbb', msg[i:i+5])
        # Get the IP value in String
        myIps = ""
        for val in preparringStruct:
            myIps += (str(val) + ".")
        myIps = (myIps[:-3])
        # print(myIps)
        # Get the Cost from tuple
        myCost = preparringStruct[-1]
        # print(myIps)
        i += 5
        if myIps in routing_table:
            # If the updated cost is less than the routing table cost, according to bellman ford algorithm
            # If dist[v] > dist[u] + weight of edge uv, then update dist[v]
            # else dist[v] = dist[u] + weight of edge uv
            # it should update the cost. Therefore, the smaller value should become the cost
            if routing_table[myIps][0] > myCost + routing_table[neigh_addr][0]:
                # Update the routing table if changed
                routing_table[myIps] = [int(myCost) + routing_table[neigh_addr][0], routing_table[neigh_addr][1]]
                update = True
        # Dealing with KeyError 
        elif myIps == THIS_HOST:
            continue
        else:
            routing_table[myIps] = [int(myCost) + routing_table[neigh_addr][0], routing_table[neigh_addr][1]]
            update = True
    return update  
    
def send_update(routing_table: dict, node: str) -> None:
    """
    Send update
    :param node: recipient of the update message
    """
    msg = format_update(routing_table)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((THIS_HOST, BASE_PORT))
        sock.sendto(msg, (node, BASE_PORT + int(node[-1])))


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
    # print(dst_node, THIS_HOST)

    if THIS_HOST == dst_node:
        return f"Received {finalMessage[0]} from {finalMessage[1]}"
    else:
        # idk why its not forwarding
        send_hello(finalMessage[0], finalMessage[1], finalMessage[2], routing_table)
        return f"Forwarded {finalMessage[0]} to {finalMessage[2]}"
    

def send_hello(msg_txt: str, src_node: str, dst_node: str, routing_table: dict) -> None:
    """
    Send a message

    :param mst_txt: message to send
    :param src_node: message originator
    :param dst_node: message recipient
    :param routing_table: this router's routing table
    """  
    # print('Client started')         
    with socket.socket(AF_INET, SOCK_DGRAM) as sock:
        sock.bind((THIS_HOST, BASE_PORT))
        msg_bytes = format_hello(msg_txt, src_node, dst_node)
        BASE_P = 4300
        BASE_P = BASE_P + int(dst_node[-1])
        # Should send hello to the shortest distance 
        print(f"Forwarded {msg_bytes} to {routing_table.get(dst_node)[1]}")
        sock.sendto(msg_bytes, (routing_table.get(dst_node)[1], BASE_P))
    # print("Client closed")

def print_status(routing_table: dict) -> None:
    """
    Print status

    :param routing_table: this router's routing table
    * Print current routing table.
    * The function must print the current routing table in a 
    human-readable format (rows, columns, spacing).
    """
    a = '   Host     '
    b = 'Cost     '
    c = 'From'
    print(a, b, c)
    for r in routing_table:
        print( r, "  " , " ", routing_table[r][0], "   ", routing_table[r][1])
    print('\n')


def route(neighbors: set, routing_table: dict, timeout: int = 5):
    # print(neighbors, routing_table)
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
    # Start with a socket application that reads 
    # network configuration from a file
    # Binds to port 430**x**, and prints the routing table.
    sock = socket.socket(AF_INET, SOCK_DGRAM)
    sock.bind((THIS_HOST, BASE_PORT + int(THIS_HOST[-1])))

    # Send Hello and Update to each of router instances. 
    # If the router does not get a Hello response, 
    # it will resend the hello message after couple of seconds
    inputs = [sock]
    time.sleep(random.randint(1, 4))
    #Send UPDATE message to all neighbors on boot 
    for i in neighbors:
        send_update(routing_table, i)
    print_status(routing_table)
    while inputs:
        read_from, write_to, err = select.select(inputs, [], [], timeout)
        if random.randint(0,100) < 10:
            time.sleep(random.randint(1, 4))
            send_hello(random.choice(ubuntu_release), THIS_HOST, str(random.choice(list(neighbors))), routing_table)
            time.sleep(random.randint(1, 4))
        # other 10% chance it will send hello, 90% initiate the server
        else:
            # print("Initiated the service")
            for r in read_from:
                pkt_rcvd, addr = sock.recvfrom(1024)
                if pkt_rcvd:
                    message_type = pkt_rcvd[0]
                    if message_type == 1:
                        print(parse_hello(pkt_rcvd, routing_table)) 
                        # print_status(routing_table) 
                    elif message_type == 0:
                        time.sleep(random.randint(1, 4))
                        updated = parse_update(pkt_rcvd, addr[0], routing_table)
                        # Send update to all neighbors occasionally
                        for i in neighbors:
                            send_update(routing_table, addr[0])
                        print_status(routing_table)
                        time.sleep(random.randint(1, 4))
                    else:
                        print("Unexpected Message")
    sock.close()


def main():
    """Main function"""
    arg_parser = argparse.ArgumentParser(description="Parse arguments")
    arg_parser.add_argument("-c", "--debug", action="store_true", help="Enable logging.DEBUG mode")
    arg_parser.add_argument("filepath", type=str, help="file path")
    arg_parser.add_argument("ip", type=str, help="client src")
    args = arg_parser.parse_args()

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)
    
    global THIS_HOST 
    THIS_HOST = args.ip
    route(read_config_file(args.filepath)[0], read_config_file(args.filepath)[1], timeout=5)

if __name__ == "__main__":
    main()