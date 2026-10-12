"""
network/client.py

TCP Client
"""

import socket


class Client:

    def __init__(self,
                 host="127.0.0.1",
                 port=5000):

        self.host = host
        self.port = port
        self.socket = None

    def connect(self):

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        self.socket.connect(
            (
                self.host,
                self.port
            )
        )

        print(
            f"Connected to {self.host}:{self.port}"
        )

    def close(self):

        if self.socket:

            self.socket.close()

            print("Connection closed.")