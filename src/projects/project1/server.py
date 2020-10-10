#!/usr/bin/env python3
"""Simple server program"""
import argparse
import logging
import socket
from csv import DictReader
from typing import Tuple
import csv

HOST = "127.0.0.1"
PORT = 4300


def read_file(filename: str) -> Tuple[dict, int]:
    """Read the world countries and their capitals from the file
    Return the tuple of (dictionary, count) where
    `dictionary` is a map {country:capital} and
    `count` is the number of countries in the world
    Make sure not to count United States of America and USA as two different countries
    """
    filename = "world.csv"
    with open(filename, "r") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        myTuple = []
        finalTuple = ()
        count = 0
        for row in reader:
            count += 1
            myTuple.append(row)     
        mappingDictionary = {sub["Country"] : sub["Capital"] for sub in myTuple}
        finalTuple = list(finalTuple)
        finalTuple.append(mappingDictionary)
        finalTuple = tuple((finalTuple))
        finalTuple = ( finalTuple  + (count, ))
        return finalTuple

def find_capital(world: dict, country: str) -> str:
    """Return the capital of a country if it exists
    Return *No such country* otherwise
    """

    myDict = {}
    for key, value in world.items():
        if "," in key:
            country_list = key.split(", ")
            for i in country_list:
                myDict[i] = value
        else:
            myDict[key] = value
    
    if country in myDict:
        return (myDict.get(country))
    else: 
        return ("No such country.")


def format(message: str) -> bytes:
    """Convert (encode) the message to bytes"""
    return message.encode()


def parse(data: bytes) -> str:
    """Convert (decode) bytes to a string"""
    return "".join(data.decode())


def server_loop(world: dict):
    print("The server has started")
    # DGRAM or use STREAM is more reliable. DBGRAM is unreliable
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        while True:
            msg, client = sock.recvfrom(2048)
            msg = msg.decode()
            if msg == "bye":
                break
            print(f"Received {msg}")
            sock.sendto(format(find_capital(world,msg)), client)

        sock.close()
    print("The server has finished")


def main():
    arg_parser = argparse.ArgumentParser(description="Enable debugging")
    arg_parser.add_argument("-f", "--file", type=str, help="File name")
    arg_parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable logging.DEBUG mode"
    )
    args = arg_parser.parse_args()

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)
    world, _ = read_file(args.file)
    server_loop(world)


if __name__ == "__main__":
    main()
