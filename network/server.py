"""
network/server.py

TCP Server
"""

import socket


class Server:

    def __init__(self,
                 host="127.0.0.1",
                 port=5000):

        self.host = host
        self.port = port

        self.server = None
        self.connection = None

    def start(self):

        self.server = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        # allow an immediate restart on the same port
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.server.bind(
            (
                self.host,
                self.port
            )
        )

        self.server.listen(1)

        print(
            f"Listening on {self.host}:{self.port}"
        )

        self.connection, address = self.server.accept()

        print("Connected:", address)

    def close(self):

        if self.connection:

            self.connection.close()

        if self.server:

            self.server.close()

        print("Server closed.")