"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM
import logging
import argparse


ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"

def response():
    # string = open('alice30.txt').read()
    # myList = []
    # for word in string.split():
    #     myList.append(word)
    # print(len(myList))
    return 14858

def server_loop():
    with socket(AF_INET, SOCK_STREAM) as server_sock:
        server_sock.bind((ADDRESS, PORT))
        server_sock.listen()
        print("The server is ready to receive")
        while True:
            connectionSocket, addr = server_sock.accept()
            request = connectionSocket.recv(1024).decode()
            print(request)
            if request:

                ip = socket.gethostbyname(http://127.0.0.2:4300)
            connectionSocket.send("Test".encode(), ADDRESS)
        connectionSocket.close()
            # if request != "/alice30.txt":
            #     connectionSocket.send()

def main():
    """Main loop"""
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
    # print(response())
    server_loop()
        

if __name__ == "__main__":
    main()
