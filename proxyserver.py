
# coding: utf-8

# # socks协议处理部分：
# 

# 认证阶段
# 
# 首先客户端需要和服务端有个握手认证的过程，可以采用 用户名/密码 认证或者无需认证方式。
# 
# 格式如下 （数字表示位数）
# 
#     +----+----------+----------+
#     |VER | NMETHODS | METHODS  |
#     +----+----------+----------+
#     | 1  |    1     |  1~255   |
#     +----+----------+----------+
# VER 字段是当前协议的版本号，也就是 5；
# NMETHODS 字段是 METHODS 字段占用的字节数；
# METHODS 字段的每一个字节表示一种认证方式，表示客户端支持的全部认证方式。
#         0x00: NO AUTHENTICATION REQUIRED
#         0x01: GSSAPI
#         0x02: USERNAME/PASSWORD
#         0x03: to X’7F’ IANA ASSIGNED
#         0x80: to X’FE’ RESERVED FOR PRIVATE METHODS
#         0xFF: NO ACCEPTABLE METHODS
# 
# 
# 服务端返回格式
# 
#     +----+--------+
#     |VER | METHOD |
#     +----+--------+
#     | 1  |   1    |
#     +----+--------+
# 一般情况下服务端返回两种情况
# 
# 0x05 0x00：告诉客户端采用无认证的方式建立连接；
# 
# 0x05 0xff：客户端的任意一种认证方式服务器都不支持。
# 
# 
# 
# 举个例子， 服务器无需认证的情况如下
# 
#     client -> server: 0x05 0x01 0x00
#     server -> client: 0x05 0x00
# 
# 
# 连接阶段
# 
# 认证完成，客户端向服务端发送请求：
# 
#     +----+-----+-------+------+----------+----------+
#     |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
#     +----+-----+-------+------+----------+----------+
#     | 1  |  1  |   1   |  1   | Variable |    2     |
#     +----+-----+-------+------+----------+----------+
# CMD 字段 command 的缩写：
#     * 0x01：CONNECT 建立 TCP 连接
#     * 0x02: BIND 上报反向连接地址
#     * 0x03：关联 UDP 请求
# RSV 字段：保留字段，值为 0x00
# ATYP 字段：address type 的缩写，取值为：
#     * 0x01：IPv4        
#     * 0x03：域名
#     * 0x04：IPv6
# DST.ADDR 字段：destination address 的缩写，取值随 ATYP 变化：
#     * ATYP == 0x01：4 个字节的 IPv4 地址
#     * ATYP == 0x03：1 个字节表示域名长度，紧随其后的是对应的域名
#     * ATYP == 0x04：16 个字节的 IPv6 地址
#     * DST.PORT 字段：目的服务器的端口
# 
# 
# 服务端返回格式
# 
#     +----+-----+-------+------+----------+----------+
#     |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
#     +----+-----+-------+------+----------+----------+
#     | 1  |  1  |   1   |  1   | Variable |    2     |
#     +----+-----+-------+------+----------+----------+
# 
# REP 字段
#     * X'00' succeeded
#     * X'01' general SOCKS server failure
#     * X'02' connection not allowed by ruleset
#     * X'03' Network unreachable
#     * X'04' Host unreachable
#     * X'05' Connection refused
#     * X'06' TTL expired
#     * X'07' Command not supported
#     * X'08' Address type not supported
#     * X'09' to X'FF' unassigned
# 
# 
# 举个例子，客户端通过 127.0.0.1:8000 的代理发送请求
# 
#     # request:        VER  CMD  RSV  ATYP DST.ADDR            DST.PORT
#     client -> server: 0x05 0x01 0x00 0x01 0x7f 0x00 0x00 0x01 0x1f 0x40
#     # response:       VER  REP  RSV  ATYP BND.ADDR            BND.PORT
#     server -> client: 0x05 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x10 0x10
# 
# 
# 传输阶段
# 
# 接下来就开始传输数据，socks5 服务器只做单纯的转发功能
# 
# 整个过程如下
# 
#     # 认证阶段
#     client -> server: 0x05 0x01 0x00
#     server -> client: 0x05 0x00
#     # 连接阶段
#     client -> server: 0x05 0x01 0x00 0x03 0x0a b'google.com'  0x00 0x50
#     server -> client: 0x05 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x10 0x10
#     # 传输阶段
#     client -> server -> remote
#     remote -> server -> client
#     ...    
# 
# 


# # 代理服务器

# ### 头文件

# In[1]:


import socket
import socketserver
from queue import Queue
from time import time,sleep
import select
import struct
import sys
import logging
import threading
import hashlib


# ### 传输函数

# In[2]:


def send_data(sock, data):
    print(data)
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


# ### socks协议处理：

# #### 传输阶段

# In[3]:


def transmit(sock, addr, desport, desaddr):
    try:
        if CCMD == 0x01:
            if CATYP == 0x01:
                sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_server.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock_server.connect((desaddr, desport))
                while True:
                    data_cli = sock.recv(1024)
                    # There is more thing to do!
                    print("Received from client:", data_cli.decode())
                    if data_cli.decode().lower() == 'exit' or not data_cli:
                        print("shutdown the client", addr)
                        break
                    sock_server.send(data_cli)
                    print("Forward finished!")
                    data_ser = sock_server.recv(1024)
                    # There is more thing to do!
                    print("Received from server:", data_ser.decode())
                    sock.send(data_ser)
                    print("Forward finished!!")
                sock.close()
                sock_server.close()
            elif CATYP == 0x04:
                sock_client = socket.socket(
                    socket.AF_INET6, socket.SOCK_STREAM)
                sock_client.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock_client.bind(("0:0:0:0:0:0:7f00:1", 8080))
                sock_server = socket.socket(
                    socket.AF_INET6, socket.SOCK_STREAM)
                sock_server.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock_server.connect((desaddr, desport))
                while True:
                    data_cli = sock_client.recv(1024)
                    # There is more thing to do!
                    print("Received from client:", data_cli.decode())
                    if data_cli.decode().lower() == 'exit' or not data_cli:
                        print("shutdown the client", addr, "\n\n")
                        break
                    sock_server.send(data_cli)
                    print("Forward finished!")
                    data_ser = sock_server.recv(1024)
                    # There is more thing to do!
                    print("Received from server:", data_ser.decode())
                    sock_client.send(data_ser)
                    print("Forward finished!!")
                sock_client.close()
                sock_server.close()
            else:
                pass
        elif CCMD == 0x02:
            pass
        elif CCMD == 0x03:
            pass
    except socket.error as oe:
        print(oe, "\nsocket error!Please check your proxy server!")


# #### 连接阶段

# In[4]:


def connection(sock, addr):
    data = sock.recv(1024)
    global CVER, CCMD, CRSV, CATYP, desadddr, desport
    CVER, CCMD, CRSV, CATYP = data[:4]
    reply = struct.pack("!3B", 0x05, 0x00, 0x00)
    try:
        if CRSV != 0x00:
            sock.close()
            return
        if CCMD == 0x01:
            if CATYP == 0x01:
                desaddr = socket.inet_ntop(socket.AF_INET, data[4:8])
                desport = struct.unpack("!H", data[8:10])
                reply += struct.pack("!B", CATYP) + data[4:10]
            elif CATYP == 0x03:
                addr_len = struct.unpack("!B", data[4:5])
                desaddr = data[5:addr_len+5]
                reply += struct.pack("!B", CATYP) + data[4:addr_len+5]
            elif CATYP == 0x04:
                desaddr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                desport = struct.unpack("!H", data[20:22])
                reply += struct.pack("!B", CATYP) + data[4:22]
            else:
                return
        elif CCMD == 0x02:
            pass
        elif CCMD == 0x03:
            pass
        else:
            return
        sock.send(reply)
        print("connection finished!\n")
        return desaddr, desport[0], sock, addr
    except struct.error as te:
        print(te, "\nProxy server struct error!!")
    except socket.error as oe:
        print(oe, "\nsocket error!Please check your proxy server!")
 


# #### 认证阶段

# In[5]:


def Author(sock, addr):
    data = sock.recv(1024)
    AVER, ANMETHODS, AMETHODS = data[:3]
    try:
        if(AVER != 0x05):
            ret = struct.pack("!BB", 0x05, 0xff)
            result = send_data(sock, ret)
            if result < len(ret):
                raise Exception('failed to send all data')
            sock.close()
            return
        while AVER == 0x05:
            if(ANMETHODS == 0x01):
                if(AMETHODS == 0x00):
                    ret = struct.pack("!BB", 0x05, 0x00)
                elif(AMETHODS == 0x02):
                    ret = struct.pack("!BB", 0x05, 0x00)
                else:
                    ret = struct.pack("!BB", 0x05, 0xff)
#             elif(ANMETHODS == 0x02 and
#                  ((AMETHODS == 0x02 and AMETHODS2 == 0x00) or
#                   (AMETHODS == 0x00 and AMETHODS2 == 0x02))):
#                 ret = struct.pack("!BB", 0x05, 0x00)
            else:
                ret = struct.pack("!BB", 0x05, 0xff)
                result = send_data(sock, ret)
                if result < len(ret):
                    raise Exception('failed to send all data')
                sock.close()
                return
            result = send_data(sock, ret)
            if result < len(ret):
                raise Exception('failed to send all data')
            print("Authenication finished!\n")
            break
        return sock, addr
    except struct.error as te:
        print(te, "\nProxy server struct error!")
    except socket.error as oe:
        print(oe, "\nsocket error!Please check your proxy server!")


# ### 整合函数

# In[6]:


def handle_uni(sock, addr):
    sock1, addr1 = Author(sock, addr)
    desaddr2, desport2, sock2, addr2 = connection(sock1, addr1)
    transmit(sock2, addr2, desport2, desaddr2)


# ### 主函数

# In[7]:


def main():
    socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    socketServer.bind(('127.0.0.1', 8080))
    socketServer.listen(5)

    try:
        while True:
            sock, addr = socketServer.accept()
            t = threading.Thread(target=handle_uni, args=(sock, addr))
            t.start()
    except socket.error as e:
        logging.error(e)


# In[ ]:


if __name__ == '__main__':
    main()


