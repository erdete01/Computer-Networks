"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM
import logging
import argparse
import time
import datetime
import json


ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"

def format(message: str) -> bytes:
    """Convert (encode) the message to bytes"""
    return message.encode()

def contentLength():
    string = open('alice30.txt').read()
    return str(len(string))

def logFile(myDictionary):
    f = open("webserver.log", "a")
    f.write(myDictionary["Time"] + " | " + 
        myDictionary["file"] + " | " + myDictionary["IP"] 
        + " | " + myDictionary["browser"] + "\n")
    f.close()

def server_loop():
    with socket(AF_INET, SOCK_STREAM) as server_sock:
        server_sock.bind((ADDRESS, PORT))
        server_sock.listen()
        myDict = {}
        print("The server is ready to receive")
        while True:
            connectionSocket, addr = server_sock.accept()
            request = connectionSocket.recv(1024).decode()
            if request:
                # print(request)
                myDict['HTTP'] = request.split( )[2]
                myDict['server'] = "CS430-Temuulen Erdenebulgan"
                myDict['date'] = time.asctime( time.localtime(time.time()) )
                myDict['file'] = request.split( )[1]
                lines = request.split( )
                browser = lines.index('User-Agent:') + 1
                myDict['browser'] = request.split( )[browser]
                myDict["Time"] = str(datetime.datetime.now())
                ip = lines.index('Host:') + 1
                
                print(request.split(":"))
                myDict["IP"] = request.split(":")[ip]
                myDict["length"] = contentLength()
                myDict["modified"] = "Friday, August 29, 2018 11:00 AM"
                myDict["content-type"] = "text/plain; charset=utf-8"
                logFile(myDict)
                # print("hello?",myDict)
                # response = myDict['HTTP'] + "200 OK" + "\n" + "Content-Length: " + myDict["length"] + "\n" + "Content-Type: " + myDict["content-type"] +"\n" + "Date: " + myDict['date'] + '\n' + "Last-Modified: " + myDict["modified"] + "\n" + "Server: " + myDict["server"]
                
                connectionSocket.sendto(format("hi"), addr)
                

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
    server_loop()
        

if __name__ == "__main__":
    main()