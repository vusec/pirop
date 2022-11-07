#!/usr/bin/python

# run function X seconds
# http://stackoverflow.com/a/14920854

import sys
import time
import multiprocessing

print int(sys.argv[1])

func_start = 48 # offset in the 256 Byte slot
bb_sizes = [120, 96, 57]*int(sys.argv[1])
#cp_in_bb = 1
#offset_in_bb = 54
#gd_in_bb = 1
#offset_in_bb = 58
#gd_len = 1

bb_dict = {}
for i in range(len(bb_sizes)):
  bb_dict[chr(ord('A')+i)] = bb_sizes[i]

num_comb = 0
def visit_all_comb_rec(bb_order):
  global num_comb

  if len(bb_order) == len(bb_dict):
    print bb_order
    num_comb += 1
    if num_comb % 1000 == 0:
      print num_comb
    return

  for bb in bb_dict:
    if bb not in bb_order:
      bb_order.append(bb)
      visit_all_comb_rec(bb_order)
      bb_order.pop()

def visit_all_comb():
  visit_all_comb_rec([])

#visit_all_comb([])
#print num_comb

if __name__ == '__main__':
  # Start foo as a process
  p = multiprocessing.Process(target=visit_all_comb, name="rec")
  p.start()

  # Wait a maximum of 10 seconds for foo
  # Usage: join([timeout in seconds])
  p.join(10)

  # If thread is active
  if p.is_alive():
    print "rec is running... let's kill it..."

    # Terminate foo
    p.terminate()
    p.join()

