"""Loopback DNS recorder for the sandbox: logs each queried name, answers NXDOMAIN."""
import socket
import sys

log = open(sys.argv[1], "a", buffering=1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 53 if len(sys.argv) < 3 else int(sys.argv[2])))
while True:
    data, peer = sock.recvfrom(4096)
    labels, position = [], 12
    while position < len(data) and data[position] and data[position] < 64:
        labels.append(data[position + 1:position + 1 + data[position]].decode("ascii", "replace"))
        position += 1 + data[position]
    log.write(".".join(labels) + "\n")
    # NXDOMAIN reply: same id, QR=1, RCODE=3, echo the question.
    sock.sendto(data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:position + 5], peer)
