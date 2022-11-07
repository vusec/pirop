#! /usr/bin/env python
import ctypes, sys, os, time
import os.path
import math
from subprocess import check_output

# Inspired from http://unix.stackexchange.com/a/6271
class AsteriskMemDumper:
  def __init__(self, num_bytes, rop_offset_in_stack, number_of_segments):
    assert(num_bytes%16==0) # must be multiple of 16 bytes
    
    self.pid = int(check_output(["pidof","asterisk"]).strip())
    self.num_segments = number_of_segments
    self.rop_offset_in_stack = rop_offset_in_stack
    self.segments = dict()
    num_lines = num_bytes / 16
    for i in range(self.num_segments):
      self.segments[i+1] = dict()
      self.segments[i+1]['dump'] = "rop_mem_dump_%d_%d" % (self.pid,i+1)
      self.segments[i+1]['signal'] = "rop_signal_file_%d_%d" % (self.pid,i+1)
      self.segments[i+1]['rop_addr'] = None
      tmp_lines = int(math.ceil( num_lines / float(number_of_segments) ))
      self.segments[i+1]['num_bytes'] = tmp_lines * 16
      num_lines -= tmp_lines
      number_of_segments -= 1
    self.ptraceInitialized = False

  def getRopAddr(self):
    maps_file = open("/proc/"+str(self.pid)+"/maps","r")
    for l in maps_file.readlines():
      if "[stack:" in l:
        rop_addr = int(l.split("-")[0],16) + self.rop_offset_in_stack
        at_offset = 0
        for k in self.segments:
          d = self.segments[k]
          d['rop_addr'] = rop_addr + at_offset
          at_offset += d['num_bytes']
        break

  def dumpRopData(self):
    time.sleep(0.2)
    for k in self.segments:
      d = self.segments[k]
      chunk = self.readRopData(d['rop_addr'], d['num_bytes'])
      self.writeToFile(chunk, d['rop_addr'], d['dump'], d['signal'])
    self.waitUntilFilesAreGone()

  def readRopData(self, rop_addr, num_bytes): 
    self.initPtrace()
    self.ptrace(True)
    mem_file = open("/proc/" + str(self.pid) + "/mem", 'r', 0)
    assert(rop_addr != None)
    mem_file.seek(rop_addr)
    chunk = mem_file.read(num_bytes)
    mem_file.close()
    self.ptrace(False)
    return chunk

  def writeToFile(self, chunk, rop_addr, dump_file_name, signal_file_name):
    dump_file = open(dump_file_name, 'w')
    for i in range(0,len(chunk),16):
      s = "0x%x:  " % (rop_addr + i)

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
    signal_file = open(signal_file_name, 'w')
    signal_file.close()

  def waitUntilFilesAreGone(self):
    while self.areFilesAvailable(): 
      #print "files are still available"
      time.sleep(0.4)
      
  def areFilesAvailable(self):
    for k in self.segments:
      d = self.segments[k]
      if os.path.isfile(d['dump']) or os.path.isfile(d['signal']):
        return True
    return False

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

class AsteriskMemPrinter:
  def __init__(self, segment_number):
    self.pid = int(check_output(["pidof","asterisk"]).strip())
    self.dump_file_name = "rop_mem_dump_%d_%d" % (self.pid, segment_number)
    self.signal_file_name = "rop_signal_file_%d_%d" % (self.pid, segment_number)

  def removeFiles(self):
    os.remove(self.dump_file_name)
    os.remove(self.signal_file_name)

  def getRopData(self):
    mem_dump = open(self.dump_file_name,'r',0)
    data = mem_dump.read()
    mem_dump.close()
    return data

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
