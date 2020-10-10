#!/usr/bin/env python3
"""Simple client program"""
import argparse
import logging
import socket

HOST = "localhost"
PORT = 4300


def format(message: list) -> bytes:
    """Convert (encode) the message to bytes"""
    return f"{''.join(message)}".encode()


def parse(data: bytes) -> str:
    """Convert (decode) bytes to a string"""
    return data.decode()


def read_user_input() -> str:
    msg = input("Enter your name: ")
    return msg
    

def client_loop():
    print("The client has started")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while True:
            msg = input("Enter your country name: ")
            logging.info(f"Connecting to {HOST}:{PORT}")
            sock.connect((HOST, PORT))
            logging.info("Formatting data")
            data_out = format(msg)
            sock.sendall(data_out)
            if msg == 'bye':
                break
            response, _ = sock.recvfrom(2048)
            message = parse(response)
            print(message)
            print(f"Recieved: {message}")
    print("The client has finished")


def main():
    arg_parser = argparse.ArgumentParser(description="Enable debugging")
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
    client_loop()


if __name__ == "__main__":
    main()
