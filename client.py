
# coding: utf-8

# # socks协议处理部分

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
# 

# # 客户端实现

# ### 头文件

# In[28]:


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


# ### socks协议处理部分

# #### 认证部分

# In[29]:


def Author(sock, addr):
    try:
        authentication = struct.pack("!B", 0x05)
        which = input(
            "please input which one you choose:\n1. NO AUTHENTICATION REQUIRED\n2. USERNAME/PASSWORD\n3. MIX")
        if(which== 1):
            authentication += struct.pack("!BB", 0x01, 0x00)
        elif(which== 2):
            authentication += struct.pack("!BB", 0x01, 0x02)
        elif(which== 3):
            authentication += struct.pack("!BBB", 0x02, 0x00, 0x02)
        if(authentication.decode() == "\x05"):
            print("NO CHOOSE ERROR!")
            sock.close()
        else:
            sock.send(authentication)
        version, method = struct.unpack("!BB", sock.recv(256))
        if(method == 0xff):
            print("Authentication failed!")
            sock.close()
    except socket.error as se:
        print("client socket error")


# #### 连接部分

# In[30]:


def connection(sock, addr):    
    global CVER, CCMD, CRSV, CATYP
    CVER=0x05 
    try:
        if CRSV != 0x00:
            sock.close()
            return
        if CCMD == 0x01:
            if CATYP == 0x01:
                desaddr = socket.inet_pton(socket.AF_INET, addr)
                data=struct.pack("!BBBB", CVER, CCMD, CRSV, CATYP)+ desaddr
            elif CATYP == 0x03:
                pass
            elif CATYP == 0x04:
                pass
            else:
                return
        elif CCMD == 0x02:
            pass
        elif CCMD == 0x03:
            pass
        else:
            return
        sock.send(data)
    except struct.error as te:
        print(te, "\nProxy server struct error!")
    except socket.error as oe:
        print(oe, "\nsocket error!Please check your proxy server!")


# In[31]:


def Author(sock, addr):
    aut = sock.recv(256)
    DVER, DREP, DRSV, DATYP = struct.unpack(
        "!4B", aut[0:4])
    try:
        if(DVER != 0x05):
            sock.close()
            return
        while DVER == 0x05:
            if(DREP != 0x00):
                sock.close()
                break
            else:
                data=input("please input:") 
                sock.send(data)
    except struct.error as te:
        print(te, "\nProxy server struct error!")
    except socket.error as oe:
        print(oe, "\nsocket error!Please check your proxy server!")


# ### 主函数

# In[32]:


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    HOST = "127.0.0.1"
    PORT = 9900
    sock.connect((HOST, PORT))
    


# # 测试代码

# In[33]:


authentication = struct.pack("!BB",0x05 ,0x00)
version, method = struct.unpack("!BB", authentication)
if method == 0x00:
    print("!!")


# In[34]:


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# 获取本地主机名
host = socket.gethostname() 

# 设置端口号
port = 9900

# 连接服务，指定主机和端口
s.connect(("127.0.0.1", port))
x=input()
# 接收小于 1024 字节的数据
s.send(x.encode("utf8"))

d = s.recv(1024)
print(d)
s.close()

