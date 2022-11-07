#from __future__ import with_statement
#from __future__ import print_function
import gdb

class FindPointers (gdb.Command):
  "Prefix command for saving things."

  def __init__ (self):
    super (FindPointers, self).__init__ ("find_pointers",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE)

  def my_print(self,s):
    if self.write_to_file != None:
      self.write_to_file.write(s)
      self.write_to_file.flush()
    else:
      gdb.write(s)
      
  def dump_maps(self,proc_pid):
    with open("/proc/%d/maps"%proc_pid,"r") as f:
      for l in f.readlines():
        self.my_print(l)


  def read_maps(self, proc_pid):
    self.maps = []
    with open("/proc/%d/maps" % proc_pid, "r") as f:
      for l in f.readlines():
        spl = l.strip().split()
        spl_addrs  = spl[0].split("-")
        first_addr = int(spl_addrs[0],16)
        last_addr  = int(spl_addrs[1],16)
        permission = spl[1]
        if(len(spl) > 5):
          region_name = spl[5]
        else:
          region_name = "[N/A]"
        self.maps.append( (first_addr, last_addr, permission, region_name) )
    

  def read_value(self, addr, proc, size):
    buf = proc.read_memory(addr, size)
    assert(len(buf)==size)
    return int.from_bytes(buf, byteorder='little')


  def parse_arg(self, arg):
    # pointers to 
    # -t(arget_space) 0x123 0x345 # exact or region
    # -s(earch_space) 0x456 0x918
    # -o(output) file
    # -d(isable_searching_in_target)
    # TODO: -a(ddr) 0x123 -l(ength) 0x345

    self.target_space_start = 0
    self.target_space_end   = 0

    self.search_space_enabled = False
    self.search_space_start   = 0
    self.search_space_end     = 0

    self.write_to_file = None

    spl = arg.split()

    for i in range(len(spl)):
      if spl[i].startswith("-t"):
        if i+2 >= len(spl) or spl[i+1][0] == '-' or spl[i+2][0] == '-':
          return False
        self.target_space_start = int(spl[i+1],16)
        self.target_space_end   = int(spl[i+2],16)
        if self.target_space_start > self.target_space_end:
          return False

      elif spl[i].startswith("-s"):
        if i+2 >= len(spl) or spl[i+1][0] == '-' or spl[i+2][0] == '-':
          return False
        self.search_space_start = int(spl[i+1],16)
        self.search_space_end   = int(spl[i+2],16)
        if self.search_space_start >= search_space_end:
          return False

        self.search_space_enabled = True
      elif spl[i].startswith("-o"):
        if i+1 >= len(spl):
          return False
        self.write_to_file = open(spl[i+1],"w")
      
      elif spl[i].startswith("-d"):
        self.searching_in_target_disabled = True
        
    if self.target_space_end == 0:
      return False

    return True


  def in_target(self,t):
    return self.target_space_start <= t <= self.target_space_end


  def search_pointers_in_mem(self,proc,m):
    s = m[0]
    e = m[1]
    p = m[2]
    n = m[3]
    
    self.my_print( "Searching in memory: 0x%X-0x%X (0x%x) %s %s ..\n" % (s,e,e-s,p,n) )

    start = s
    end = e - 6 # 7 # XXX 64 bit
    if self.search_space_enabled:
      if self.search_space_start > end or self.search_space_end < start:
        self.my_print( "  Not in search space.. skip..\n" )
        return

      if self.search_space_start > start:
        start = self.search_space_start
      if self.search_space_end < end:
        end = self.search_space_end 

    counter = 0
    for a in range(start, end, self.step_size):
      try:
        if self.searching_in_target_disabled:
          if self.target_space_start <= a < self.target_space_end:
            continue

        t = self.read_value(a, proc, 8)
        if self.in_target(t):
          counter += 1
          self.my_print("  %d: 0x%X -> 0x%X\n" % (counter, a, t))
      except gdb.MemoryError:
        continue

    
  def search_pointers(self,proc):
    self.my_print("Searching pointers to: [0x%X-0x%X]\n" % (self.target_space_start, self.target_space_end) )
    if self.searching_in_target_disabled:
      self.my_print( "Searching pointers in target space is DISABLED.. \n" )
    for m in self.maps:
      self.search_pointers_in_mem(proc,m) 
      
  def geval(self,s):
    return gdb.parse_and_eval(s)
    
  def dump_regs(self):
    self.my_print("================= REGISTERS ===============\n")
    self.my_print("$RAX = 0x%016X - $R8  = 0x%016X\n" % (self.geval("$rax"),self.geval("$r8")) )
    self.my_print("$RBX = 0x%016X - $R9  = 0x%016X\n" % (self.geval("$rbx"),self.geval("$r9")) )
    self.my_print("$RCX = 0x%016X - $R10 = 0x%016X\n" % (self.geval("$rcx"),self.geval("$r10")) )
    self.my_print("$RDX = 0x%016X - $R11 = 0x%016X\n" % (self.geval("$rdx"),self.geval("$r11")) )       
    self.my_print("$RDI = 0x%016X - $R12 = 0x%016X\n" % (self.geval("$rdi"),self.geval("$r12")) )
    self.my_print("$RSI = 0x%016X - $R13 = 0x%016X\n" % (self.geval("$rsi"),self.geval("$r13")) )
    self.my_print("$RBP = 0x%016X - $R14 = 0x%016X\n" % (self.geval("$rbp"),self.geval("$r14")) )
    self.my_print("$RSP = 0x%016X - $R15 = 0x%016X\n" % (self.geval("$rsp"),self.geval("$r15")) )
    self.my_print("$RIP = 0x%016X\n" % (self.geval("$rip")) )
    self.my_print("===========================================\n")

  def invoke (self, arg, from_tty):
    self.step_size = 8 # through memory space
    self.searching_in_target_disabled = False
    self.write_to_file = None

    proc = gdb.selected_inferior()
    #procs = gdb.inferiors()
    #assert(len(procs)==1)
    #proc = procs[0]

    self.read_maps(proc.pid)
    ok = self.parse_arg(arg)
    if not ok:
      gdb.write("Parsing [arg='%s'] failed..\n" % arg)
      # XXX raise gdb.GdbError("..")
      return

    if self.write_to_file != None:
      gdb.write("Writing output to file: [%s]\n" % self.write_to_file.name)

    self.dump_regs()
    self.search_pointers(proc)
    #self.dump_maps(proc.pid)
  
    if self.write_to_file != None:
      self.write_to_file.close()
       

  

      #print (arg,".", from_tty, "\n" , file=f)
      #print (gdb.inferiors(), file=f)
      #print (gdb.selected_inferior().pid, file=f)


FindPointers()
