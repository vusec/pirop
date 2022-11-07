#! /usr/bin/env python
import ctypes, sys, os, time
import os.path
from subprocess import check_output

# Inspired from http://unix.stackexchange.com/a/6271
class AsteriskMemDumper:
  def __init__(self):
    self.pid = int(check_output(["pidof","asterisk"]).strip())
    self.dump_file_name = "rop_mem_dump_%d" % self.pid
    self.signal_file_name = "rop_signal_file_%d" % self.pid
    self.rop_addr = None
    self.ptraceInitialized = False

  def getRopAddr(self, rop_offset_from_start):
    maps_file = open("/proc/"+str(self.pid)+"/maps","r")
    for l in maps_file.readlines():
      if "[stack:" in l:
        self.rop_addr = int(l.split("-")[0],16) + rop_offset_from_start
        break

  def dumpRopData(self, num_bytes):
    time.sleep(0.2)
    chunk = self.readRopData(num_bytes)
    self.writeToFile(chunk)
    self.waitUntilFileIsGone()

  def readRopData(self, num_bytes): 
    self.initPtrace()
    self.ptrace(True)
    mem_file = open("/proc/" + str(self.pid) + "/mem", 'r', 0)
    assert(self.rop_addr != None)
    mem_file.seek(self.rop_addr)
    chunk = mem_file.read(num_bytes)
    mem_file.close()
    self.ptrace(False)
    return chunk

  def writeToFile(self, chunk):
    dump_file = open(self.dump_file_name, 'w')
    for i in range(0,len(chunk),16):
      s = "0x%x:  " % (self.rop_addr + i)

      tmp = "0x"
      for x in reversed(range(i, i+8)):
        tmp += "%02X" % ord(chunk[x])
      s += tmp + "  "

      tmp = "0x"
      for x in reversed(range(i+8, i+16)):
        tmp += "%02X" % ord(chunk[x])
      s += tmp + "  "

      s += "\n"

      dump_file.write(s)
      
    dump_file.close()

    # dump signal file
    signal_file = open(self.signal_file_name, 'w')
    signal_file.close()

  def waitUntilFileIsGone(self):
    while self.areFilesAvailable(): 
      #print "files are still available"
      time.sleep(0.4)

  def waitForSignal(self):
    secondsToWait = 60.0
    sleepSteps = 0.1
    cnt = secondsToWait / sleepSteps
    while not os.path.isfile(self.signal_file_name):
      if cnt == 0:
        return 0
      time.sleep(sleepSteps)
      cnt -= 1
    
    return 1
      
  def areFilesAvailable(self):
    return os.path.isfile(self.dump_file_name) or os.path.isfile(self.signal_file_name)

  def initPtrace(self):
    if self.ptraceInitialized: return
    self.c_ptrace = ctypes.CDLL("libc.so.6").ptrace
    self.c_pid_t = ctypes.c_int32 # This assumes pid_t is int32_t
    self.c_ptrace.argtypes = [ctypes.c_int, self.c_pid_t, ctypes.c_void_p, ctypes.c_void_p]
    self.ptraceInitialized = True
  
  ## Partial interface to ptrace(2), only for PTRACE_ATTACH and PTRACE_DETACH.
  def ptrace(self, attach):
    op = ctypes.c_int(16 if attach else 17) #PTRACE_ATTACH or PTRACE_DETACH
    c_pid = self.c_pid_t(self.pid)
    null = ctypes.c_void_p()
    #err = self.c_ptrace(op, c_pid, null, null)
    #if err != 0: raise SysError, 'ptrace', err
    while True:
      err = self.c_ptrace(op, c_pid, null, null)
      if err == 0:
        break
      #print "err = %d, retry" % err
      time.sleep(0.5)

  def getRopData(self):
    mem_dump = open(self.dump_file_name,'r',0)
    data = mem_dump.read()
    mem_dump.close()
    return data

  def removeFiles(self):
    os.remove(self.dump_file_name)
    os.remove(self.signal_file_name)

#m = AsteriskMemDumper()
#raw_input("Press Enter if ready to get rop addr")
#m.getRopAddr(0x395a0)
#raw_input("Press Enter if ready to dump rop data")
#m.dumpRopData(112 * 8)
#raw_input("Press Enter if ready to dump rop data")
#m.dumpRopData(112 * 8)
#raw_input("Press Enter if ready to dump rop data")
#m.dumpRopData(112 * 8)
#raw_input("Press Enter if ready to quit script")
