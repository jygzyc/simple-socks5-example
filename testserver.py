
# coding: utf-8

# # 测试服务器

# In[1]:


import sys
import socket
import threading
import struct


# In[ ]:


# 回复消息，原样返回


def replyMessage(conn, addr):
    while True:
        data = conn.recv(1024)
        data += b"!"
        conn.send(data)
        if data.decode().lower() == 'exit':
            break
    conn.close()


def main():
    sockScr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockScr.bind(('127.0.0.1', 9900))
    sockScr.listen(200)
    while True:
        try:
            conn, addr = sockScr.accept()
            # 创建并启动线程
            t = threading.Thread(target=replyMessage, args=(conn, addr))
            t.start()
        except:
            print('error')


if __name__ == '__main__':
    main()

