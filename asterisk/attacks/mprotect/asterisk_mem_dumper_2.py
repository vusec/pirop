#!/usr/bin/python

from asterisk_class_mem_dumper import AsteriskMemPrinter
import time
import os

os.system("clear")
print "Waiting for thread which will execute the ROP chain to start..."
a = AsteriskMemPrinter(2)
while a.waitForSignal():
  os.system("clear")
  print a.getRopData()
  a.removeFiles()
  time.sleep(0.1)

print "waiting for signal timed out"
