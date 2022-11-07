#!/usr/bin/python

import sys

num_success = 0
num_lines = 0
offsets_in_256B_slot = {}

#line:
# <cp&gadgets(s) in same 256B slot?: y/n> <gadget(s) split at 256B slot boundary> <offset of gadget range in 256B slot>

with open(sys.argv[1]) as f:
  for l in f.xreadlines():
    if len(l.strip()) < 5: continue
    num_lines += 1
    offsets_in_256B_slot[l[4:].strip()] = l[2]
    if l[0] == 'y':
      num_success += 1

print offsets_in_256B_slot

offsets_not_split = 0
for k in offsets_in_256B_slot:
  v = offsets_in_256B_slot[k]
  if v == 'n':
    offsets_not_split += 1

if num_lines == 0:
  print "no results. exiting.."
  sys.exit(0)

print "#offsets_in_256B_slot:", len(offsets_in_256B_slot)
print "#success / #total-attempts: %d/%d (%.2f%%)" % (num_success,num_lines,float(num_success)/num_lines*100)
print "non-split-offsets / total-offsets in 256B slot: %d/%d" % (offsets_not_split,len(offsets_in_256B_slot))

