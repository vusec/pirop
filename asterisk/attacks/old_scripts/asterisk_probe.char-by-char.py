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
for i in range(len(h1)):
  raw_input("Press Enter to send char: %s" % h1[i])
  s.send(h1[i])

raw_input("Press Enter to send header:Host.. ")
h2 = "Host: localhost\r\n"
print "sending:", h2
for i in range(len(h2)):
  raw_input("Press Enter to send char: %s" % h2[i])
  s.send(h2[i])

raw_input("Press Enter close connection and finish the script")
s2.close()
