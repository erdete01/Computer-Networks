"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM
import logging


ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"


def main():
    """Main loop"""
    with socket(AF_INET, SOCK_STREAM) as server_sock:
        server_sock.bind((ADDRESS, PORT))
        server_sock.listen()
        print("The server is ready to receive")
        while True:
            connectionSocket, addr = server_sock.accept()
            request = connectionSocket.recv(1024).decode()
            print("test?",request)

            connectionSocket.send("Test".encode())
            connectionSocket.close()
            # if request != "/alice30.txt":
            #     connectionSocket.send()

        

if __name__ == "__main__":
    main()
