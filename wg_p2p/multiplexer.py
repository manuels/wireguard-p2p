import socket
import selectors

class Multiplexer(object):
    intern_sock_to_extern_host = {}
    extern_host_to_intern_sock = {}
    new_sockets = []

    def __init__(self, extern_port, intern_ports):
        self.extern_port = extern_port
        self.intern_ports = intern_ports
        self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.proxy_sock.bind(('0.0.0.0', extern_port))

        self.sel = selectors.DefaultSelector()
        self.sel.register(self.proxy_sock, selectors.EVENT_READ)


    def register(self, extern_host, intern_socket=None, intern_bind_port=0):
        extern_addr, extern_port = extern_host
        extern_addr = socket.gethostbyname(extern_addr)
        extern_host = (extern_addr, extern_port)

        if extern_host in self.extern_host_to_intern_sock:
            intern_socket = self.extern_host_to_intern_sock[extern_host]
            intern_addr, intern_bind_port = intern_socket.getsockname()
            return intern_addr, intern_bind_port

        if intern_socket is None:
            intern_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            intern_socket.bind(('127.0.0.1', intern_bind_port))

        self.new_sockets.append(intern_socket)
        intern_addr, intern_bind_port = intern_socket.getsockname()
        self.intern_sock_to_extern_host[intern_socket] = extern_host
        self.extern_host_to_intern_sock[extern_host] = intern_socket

        return intern_addr, intern_bind_port


    def multiplex(self):
        for sock in self.new_sockets:
            self.sel.register(sock, selectors.EVENT_READ)
        self.new_sockets = []

        for key, mask in self.sel.select():
            insock = key.fileobj
            data, src = insock.recvfrom(2048)

            if insock == self.proxy_sock:
                if src not in self.extern_host_to_intern_sock:
                    intern_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    intern_socket.bind(('127.0.0.1', 0))
                    self.intern_sock_to_extern_host[intern_socket] = src
                    self.extern_host_to_intern_sock[src] = intern_socket

                outsock = self.extern_host_to_intern_sock[src]
                for port in self.intern_ports:
                    dst = ('127.0.0.1', port)
                    #print('{}:{} => {}:{} => {}:{}'.format(*src, *outsock.getsockname(), *dst))
                    outsock.sendto(data, dst)
            else:
                dst = self.intern_sock_to_extern_host[insock]
                #print('{}:{} => {}:{} => {}:{}'.format(*src, *self.proxy_sock.getsockname(), *dst))
                self.proxy_sock.sendto(data, dst)

