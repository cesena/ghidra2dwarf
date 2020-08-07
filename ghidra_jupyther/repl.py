import socket
import struct

PWD = 'LOLOLOLOLPWDPWD'

def read_byte(sock):
    return ord(sock.recv(1))

def write_byte(sock, b):
    return sock.send(chr(b))

def read_packet(sock):
    toread = struct.unpack('<l', sock.recv(4))[0]
    buf = bytearray(toread)
    view = memoryview(buf)
    while toread:
        nbytes = sock.recv_into(view, toread)
        view = view[nbytes:]
        toread -= nbytes
    return buf

def write_packet(sock, msg):
    sock.sendall(struct.pack('<l', len(msg)))
    return sock.sendall(msg)

def crypt_pwd(pwd, x):
    return bytearray(b ^ x for b in bytearray(pwd))

class GhidraJythonRepl:
    def __init__(self):
        server_address = ('localhost', 6666)
        sock = self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)
        b = read_byte(sock)
        write_packet(sock, crypt_pwd(PWD.encode(), b))

    def repl(self, code):
        sock = self.sock
        write_packet(sock, code.encode())
        out = read_packet(sock)
        return bytes(out).decode()

    def kill(self):
        self.sock.close()
