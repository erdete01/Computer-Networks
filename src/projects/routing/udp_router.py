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


THIS_HOST = "127.0.0.1"
BASE_PORT = 4300


def read_config_file(filename: str) -> Tuple[Set, Dict]:
    """
    Read config file

    :param filename: name of the configuration file
    :return tuple of the (neighbors, routing table)
    """
    raise NotImplementedError


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
    print(msg, "This is message", neigh_addr, "This is neighbor's addr", routing_table, "This is routing table")


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
    print(msg, routing_table)


def send_hello(msg_txt: str, src_node: str, dst_node: str, routing_table: dict) -> None:
    """
    Send a message

    :param mst_txt: message to send
    :param src_node: message originator
    :param dst_node: message recipient
    :param routing_table: this router's routing table
    """
    raise NotImplementedError


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
    raise NotImplementedError


if __name__ == "__main__":
    main()
