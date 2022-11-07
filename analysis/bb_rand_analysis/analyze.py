#!/usr/bin/python

# run function X seconds
# http://stackoverflow.com/a/14920854

import time
import multiprocessing
import random
import sys

x = sys.argv[1]

#if x == 'ast_1_cp_40de': from ast_1_cp_40de import *
if x == 'ast_12_cp_cb18': from ast_12_cp_cb18 import *
elif x == 'ast_1_cp_5001a': from ast_1_cp_5001a import *
elif x == 'ast_2_cp_5001a': from ast_2_cp_5001a import *
elif x == 'ast_1_cp_ae88': from ast_1_cp_ae88 import *
#elif x == 'ast_1_cp_bece': from ast_1_cp_bece import *
#elif x == 'ast_12_cp_c6f59': from ast_12_cp_c6f59 import *
else: sys.exit(0)

bb_dict = {}

# works for up to 2 basic blocks: cp in 1 bb and gadgets in another bb
def check_rand(keys):
  cp_in_256B_slot = 0
  gadgets_start_in_256B_slot = 0
  gadgets_start_offset_in_256B = 0
  gadgets_split_at_256B_boundary = False

  pos = func_start
  for k in keys:
    bb_len = bb_dict[k]
    if k == cp_in_bb:
      cp_in_256B_slot = (pos + cp_offset_in_bb)/256

    if k == gd_in_bb:
      gadgets_start_in_256B_slot = (pos + gd_offset_in_bb) / 256
      gadgets_start_offset_in_256B = (pos + gd_offset_in_bb) % 256
      gadgets_split_at_256B_boundary = gadgets_start_in_256B_slot != ((pos+gd_offset_in_bb+gd_len-1)/256)

    pos += bb_len

  #print keys
  #print cp_in_256B_slot
  #print gadgets_start_in_256B_slot 
  #print gadgets_start_offset_in_256B 
  #print gadgets_split_at_256B_boundary

  if gadgets_start_in_256B_slot == cp_in_256B_slot and not gadgets_split_at_256B_boundary:
    print 'y', 'n', gadgets_start_offset_in_256B
  else:
    if gadgets_split_at_256B_boundary:
      print 'n', 'y', gadgets_start_offset_in_256B
    else:
      print 'n', 'n', gadgets_start_offset_in_256B
    

def visit_all_comb():
  for i in range(len(bb_sizes)):
    bb_dict[i] = bb_sizes[i]
  bb_keys = bb_dict.keys()

  while True:
  #for i in range(10):
    random.shuffle(bb_keys)
    check_rand(bb_keys)    

#visit_all_comb([])
#print num_comb

if __name__ == '__main__':
  # Start foo as a process
  p = multiprocessing.Process(target=visit_all_comb, name="rec")
  p.start()

  # Wait a maximum of 10 seconds for foo
  # Usage: join([timeout in seconds])
  p.join(RUNTIME)

  # If thread is active
  if p.is_alive():
    #print "rec is running... let's kill it..."

    # Terminate foo
    p.terminate()
    p.join()

