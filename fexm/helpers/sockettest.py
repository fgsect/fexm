import time

from helpers import utils

import socket
import threading

tcp_port = 53007
ws_port = 53008

sock = socket.socket()
sock.bind(("0.0.0.0", tcp_port))
sock.listen(1)


def actual_parrot(sock):
    try:
        buf = b"Hi to the friendly perrot.\n"
        sock.send(buf)
        while len(buf) > 0:
            buf = sock.recv(4096)
            sock.send(buf)
    except Exception as ex:
        print("Exception: {}".format(ex), ex)
    finally:
        sock.close()


def parrot():
    try:
        while True:
            ssock, _ = sock.accept()
            threading.Thread(target=actual_parrot, args=[ssock], daemon=True).start()

    finally:
        sock.close()


threading.Thread(target=parrot, daemon=True).start()

# Thread(target=lambda: nc(l=tcp_port), daemon=True).start()
utils.forward_port_to_websocket(tcp_port, ws_port)
while True:
    time.sleep(10)
