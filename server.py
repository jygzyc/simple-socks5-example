'''
TODO:
Block connections to certain IPs / Regions
Allow for bind requests (version 4 and 5)
Implement User/Pass login (version 5)
Allow for UDP connections (version 5)
IPv6 Not Implemented (version 5)
'''

from socket import *
from struct import *
from select import select
from queue import Queue
from time import sleep, time
import sys
import threading

PORT = 8080

DEBUG_MODE = False
LOGGING = False

'''
Authentication Methods For socksv5:
    0x00: 'None'
    0x01: 'GSSAPI'
    0x02: 'User/Pass'
    0xFF: 'Not Acceptable'}
'''
ALLOWED_AUTH_METHODS = set([0x00])

logFile = None
if LOGGING:
    logFile = open('socks.log', 'w')

class Handler(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.__sock = sock
        self.__targetSock = None
        self.__sock_data = {'ip': sock.getpeername()[0], 'port': sock.getpeername()[1]}
        self.__running = True

    def __die(self):
        try:
            self.__sock.shutdown(SHUT_RDWR)
            self.__sock.close()
            self.__sock = None
        except:
            pass
        if self.__targetSock != None:
            try:
                self.__targetSock.shutdown(SHUT_RDWR)
                self.__targetSock.close()
                self.__targetSock = None
            except:
                pass
    def __loginHandler(self):
        pass

    def __init_proxy(self):
        # Client's Initial Statement
        self.__sock_data['socks_version'] = unpack('!B', self.__sock.recv(1))[0]
        if self.__sock_data['socks_version'] == 0x04:
            self.__init_proxy_4()
        elif self.__sock_data['socks_version'] == 0x05:
            self.__init_proxy_5()

    def __init_proxy_4(self):
        command, port, ip = unpack('!BHL', self.__sock.recv(7))
        self.__sock_data['command'] = command
        self.__sock_data['target_port'] = port
        self.__sock_data['target_ip'] = ip

        userID = ''
        d = unpack('!B', self.__sock.recv(1))[0]
        while d != 0:
            userID += str(chr(d))
            d = unpack('!B', self.__sock.recv(1))[0]
        self.__sock_data['user_id'] = userID

        # If IP is invalid (First 3 bytes are NULL), get the domain name at the end
        if ip < 256:
            domainName = ''
            d = unpack('!B', self.__sock.recv(1))[0]
            while d != 0:
                domainName += str(chr(d))
                d = unpack('!B', self.__sock.recv(1))[0]
            self.__sock_data['target_ip'] = domainName

        # Setup target socket
        status = 0x5A
        try:
            self.__targetSock = socket(AF_INET, SOCK_STREAM)
            self.__targetSock.connect((self.__sock_data['target_ip'], port)) # target_ip is used so we don't need to track if socks 4 or 4a
        except:
            status = 0x5B
        # Send response back to client
        response = pack('!BBHL', 0x00, status, port, ip)
        self.__sock.sendall(response)

        if status == 0x5B:
            self.__die()

    def __init_proxy_5(self):
        authentMethods = unpack('<B', self.__sock.recv(1))[0]
        self.__sock_data['auth_methods'] = unpack('<' + 'B' * authentMethods, self.__sock.recv(authentMethods))

        # Server Response
        response = pack('<B', 5)
        # Determine auth method to use
        methods = list(ALLOWED_AUTH_METHODS & set(self.__sock_data['auth_methods']))
        # Set Auth method decided
        method = 0xFF # Defaults to not supported
        if 0x00 in methods:
            # No auth needed
            method = 0x00
        elif 0x02 in methods:
            # User/Pass auth needed
            method = 0x02
        response += pack('<B', method)
        self.__sock.sendall(response)
        if method == 0xFF:
            self.__die()
            return
        elif method == 0x02:
            self.__loginHandler()

        # Setup client's request
        data = self.__sock.recv(4)
        version, command, dead, addrType = unpack('<BBBB', data)
        self.__sock_data['addr_type'] = addrType
        self.__sock_data['command'] = command

        if version != 0x05:
            self.__die()
            return

        # Get Target IP
        ip = None
        if addrType == 0x01:
            # IPv4
            ip = unpack('!L', self.__sock.recv(4))[0]
            self.__targetSock = socket(AF_INET, SOCK_STREAM)
        elif addrType == 0x03:
            # Domain Name (TODO)
            domainLength = unpack('!B', self.__sock.recv(1))[0]
            ip = ''
            for i in range(domainLength):
                d = unpack('!B', self.__sock.recv(1))[0]
                ip += str(chr(d))
            self.__targetSock = socket(AF_INET, SOCK_STREAM)
        elif addrType == 0x04:
            # IPv6 (TODO)
            ip = unpack('!LLLL', self.__sock.recv(16))
            print(ip)
            ip = ip[0]
            self.__targetSock = socket(AF_INET6, SOCK_STREAM)

        # Get Target Port
        port = unpack('!H', self.__sock.recv(2))[0]

        # Save Data
        self.__sock_data['target_ip'] = ip
        self.__sock_data['target_port'] = port

        # Connect to Target
        status = 0x00
        if ip == None:
            status = 0x08
        else:
            try:
                self.__targetSock.connect((str(ip), port))
            except Exception as e:
                status = 0x01
        self.__sock_data['status'] = status

        # Generate response to client
        response = pack('!BBBB', 0x05, status, 0x00, addrType)
        if addrType == 0x01:
            response += pack('!L', ip) # Packing for IPv4
        elif addrType == 0x03:
            # Packing for a domain name
            response += pack('!B', len(ip))
            for l in ip:
                response += pack('!B', ord(l))
        elif ipLen == 16:
            # Packing for IPv6
            response += pack('!L', ip)
        response += pack('!H', port)
        self.__sock.sendall(response)
        # Kill connection if not able to proxy
        if status == 0x01:
            self.__die()

    def __connector(self):
        self.__targetSock.settimeout(2)
        self.__sock.settimeout(2)

        socks = [self.__targetSock, self.__sock]

        # Used to hold data should one side be sending lots of data and the other side not able to immediatly recv
        sockQueue = Queue()
        targetSockQueue = Queue()

        # If more than 5 seconds elapsed since last data transfer, close the proxy session
        start = time()
        while time() - start < 5 and self.__running:
            readable, writable, error = select(socks, socks, socks)
            if self.__sock in readable:
                targetSockQueue.put(self.__sock.recv(1024 * 100))
            if self.__targetSock in readable:
                sockQueue.put(self.__targetSock.recv(1024 * 100))
            if not sockQueue.empty() and not targetSockQueue.empty():
                start = time()
            if self.__sock in writable and sockQueue.qsize() > 0:
                self.__sock.sendall(sockQueue.get())
            if self.__targetSock in writable and targetSockQueue.qsize() > 0:
                self.__targetSock.sendall(targetSockQueue.get())
    # Public Functions
    def getData(self):
        return self.__sock_data
    def run(self):
        # Initialize the connection
        self.__init_proxy()
        if DEBUG_MODE:
            sys.stdout.write('\n' + str(self.__sock_data))
            sys.stdout.flush()

        if LOGGING:
            logFile.write(self.__sock_data['target_ip'] + "\t" + str(self.__sock_data['target_port']) +\
            "\t" + gethostbyname(self.__sock_data['target_ip']) + '\n')
            logFile.flush()
        # If connection to target is successful, start proxying traffic
        if self.__targetSock != None:
            try:
                self.__connector()
            except:
                pass
            self.__die()
    def stop(self):
        self.__running = False

class Tracker(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.name = 'Tracker'
        self.__running = True
    def run(self):
        while self.__running:
            sys.stdout.write('\rActive Connections: ' + str(threading.activeCount() - 2))
            sys.stdout.flush()
            sleep(1)
    def stop(self):
        self.__running = False

class Server():
    def __init__(self):
        self.__server = socket(AF_INET, SOCK_STREAM)
        self.__server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.__tracker = None
    def __startTracker(self):
        # Start a tracker thread to watch the current number of active connections
        if self.__tracker == None:
            self.__tracker = Tracker()
            self.__tracker.start()
    def startServer(self):
        self.__server.bind(('localhost', PORT))
        self.__server.listen(10)

        print('Server Started on port %d\n' % PORT)
        if DEBUG_MODE:
            self.__startTracker()
        try:
            while True:
                conn, addr = self.__server.accept()
                handler = Handler(conn)
                handler.start()
        # If an Exception happens, kill all threads
        except KeyboardInterrupt:
            for t in threading.enumerate():
                if t.name != 'MainThread':
                    t.stop()
                    t.join()
            print('Exiting')
        except Exception as e:
            print(e)
            for t in threading.enumerate():
                if t.name != 'MainThread':
                    t.stop()
                    t.join()
            print('Exiting')

if __name__ == '__main__':
    server = Server()
    server.startServer()
