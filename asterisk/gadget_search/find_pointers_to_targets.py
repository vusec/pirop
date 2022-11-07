#from __future__ import with_statement
#from __future__ import print_function
import gdb
from time import sleep

# TODO low prior: at every command dump it to a new directory, optional..
# get exact tls start and end address for secondary threads and main-thread
# get exact stack start and end address for secondary threads and main-thread

def fprint(f,s):
  f.write(s)
  f.flush()

def g_dbg():
  return 0

def get_app_name():
  return gdb.current_progspace().filename.split('/')[-1]

def gexec(s):
  gdb.execute(s)

def geval(s):
  return gdb.parse_and_eval(s)

def gprint(s):
  gdb.write("[+] "+s)

def get_value_eval(s):
  if(g_dbg()): gprint("get_value_eval(%s) ....\n" % s)
  x = "%s"%geval(s)
  x = x.split()[0]
  if(g_dbg()): gprint(x+"\n")
  res = int(x,16)
  if(g_dbg()): gprint("get_value_eval(%s) done\n" % s)
  return res

def set_value_eval(s,val):
  gexec( "set %s=0x%x" % (s,val) )

def get_value_ptr(p):
  return get_value_eval( "{long}(0x%x)" % (p) )
  
def set_value_ptr(p,val):
  set_value_eval( "{long}(0x%x)" % (p) ,val)

def get_tcb_base():
  gexec("call arch_prctl(0x1003,$rsp-8)")  # 0x1003 = ARCH_GET_FS
  tcb_base = get_value_eval("{long}($rsp-8)")
  set_value_eval("{long}($rsp-8)", 0)
  return tcb_base
   
def get_stack_addr_and_size():
  tcb_base = get_tcb_base()
  stackblock_addr = get_value_ptr(tcb_base + 0x690)
  stackblock_size = get_value_ptr(tcb_base + 0x698)
  if stackblock_addr == 0:
    # we are on main-thread
    with open("/proc/%d/maps" % gdb.selected_inferior().pid, "r") as f:
      for l in f.readlines():
        if "[stack]" in l:
          spl = l.strip().split()
          spl_addrs = spl[0].split("-")
          stackblock_addr = int(spl_addrs[0],16)
          stackblock_size = int(spl_addrs[1],16) - stackblock_addr

  if(g_dbg()): gprint("stackblock addr = 0x%x (+0x%x)\n" % (stackblock_addr,stackblock_size))
  return (stackblock_addr, stackblock_size)

def get_tls_addr_and_size():
  rtld_global_base = get_value_eval("&_rtld_global")
  tls_tcb_size = get_value_ptr(rtld_global_base + 0xf40) # _dl_tls_static_size

  tcb_base = get_tcb_base()

  struct_pthread_size = get_value_eval("sizeof(struct pthread)")

  #gprint("tcb_base = 0x%x\n" % tcb_base)
  #gprint("f30 = 0x%x\n" % get_value_ptr(rtld_global_base + 0xf30))
  #gprint("f38 = 0x%x\n" % get_value_ptr(rtld_global_base + 0xf38))
  #gprint("dl_tls_static_size = 0x%x\n" % tls_tcb_size)
  #gprint("f48 = 0x%x\n" % get_value_ptr(rtld_global_base + 0xf48))
  #gprint("f50 = 0x%x\n" % get_value_ptr(rtld_global_base + 0xf50))
  #gprint("f58 = 0x%x\n" % get_value_ptr(rtld_global_base + 0xf58))
  
  tls_base = tcb_base - (tls_tcb_size - struct_pthread_size)
  
  return (tls_base, tls_tcb_size)
  
def is_main_thread(stack_addr, stack_size, tls_addr):
  return not (stack_addr <= tls_addr < stack_addr + stack_size)

def get_only_stack_addr_and_size(stack_addr, stack_size, tls_addr):
  only_stack_start = stack_addr

  if is_main_thread(stack_addr, stack_size, tls_addr):
    # we are in main_thread
    only_stack_end = get_value_eval("__libc_stack_end")
  else:
    # we are in secondary thread
    only_stack_end = tls_addr  
  
  return (only_stack_start, only_stack_end - only_stack_start)

def read_maps(proc_pid):
  res = []

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
      res.append( (first_addr, last_addr, permission, region_name) )

  return res

class FindPointersToTargets(gdb.Command):
  "Prefix command for saving things."

  def __init__ (self):
    super (FindPointersToTargets, self).__init__ ("ss_find_ptrs_to_targets",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE)

  def dump_regs(self):
    fprint(self.out,"================= REGISTERS ===============\n")
    fprint(self.out,"$RAX = 0x%016X - $R8  = 0x%016X\n" % (geval("$rax"),geval("$r8")) )
    fprint(self.out,"$RBX = 0x%016X - $R9  = 0x%016X\n" % (geval("$rbx"),geval("$r9")) )
    fprint(self.out,"$RCX = 0x%016X - $R10 = 0x%016X\n" % (geval("$rcx"),geval("$r10")) )
    fprint(self.out,"$RDX = 0x%016X - $R11 = 0x%016X\n" % (geval("$rdx"),geval("$r11")) )       
    fprint(self.out,"$RDI = 0x%016X - $R12 = 0x%016X\n" % (geval("$rdi"),geval("$r12")) )
    fprint(self.out,"$RSI = 0x%016X - $R13 = 0x%016X\n" % (geval("$rsi"),geval("$r13")) )
    fprint(self.out,"$RBP = 0x%016X - $R14 = 0x%016X\n" % (geval("$rbp"),geval("$r14")) )
    fprint(self.out,"$RSP = 0x%016X - $R15 = 0x%016X\n" % (geval("$rsp"),geval("$r15")) )
    fprint(self.out,"$RIP = 0x%016X\n" % (geval("$rip")) )
    fprint(self.out,"===========================================\n")

  def dump_backtrace(self):
    # loop through frames until None is reached
    fprint(self.out,"================= BACKTRACE ===============\n")
    frame = gdb.selected_frame()
    fid = 0
    while frame:
      fr_name = ""
      if frame.name():
        fr_name = frame.name()
      fprint(self.out, "%d: %X %s\n" % (fid, frame.pc(), fr_name) )
      frame = frame.older()
      fid += 1

    fprint(self.out,"===========================================\n")
      

  def dump_target_stats(self, targets):
    for t_name in targets:
      start = targets[t_name][0]
      end = targets[t_name][1]
      all_ptrs = targets[t_name][2] 
      external_ptrs = targets[t_name][3]
      fprint(self.out, " - (0x%X-0x%X) %s: all=%d ext=%d\n" % (start, end, t_name, all_ptrs, external_ptrs) )

  def dump_results(self):
    # go through threads
    fprint(self.out, "====\n")
    fprint(self.out, "Number of threads = %d\n" % len(self.threads) )
    for thr in self.threads:
      tid = thr["id"]
      lwpid = thr["lwpid"]
      gexec("thread 0x%x"%tid)
      fprint(self.out, "\n+ Thread %d - %d:\n" % (tid,lwpid))
      self.dump_target_stats(thr["targets"])
      self.dump_regs()
      self.dump_backtrace()


  def check_target(self,c, src, dst):
    if not (self.most_lower_target_addr <= dst <= self.most_upper_target_addr):
      return
  
    printed_src_dst = False
    for thr in self.threads:
      for t_name in thr["targets"]:
        t_range = thr["targets"][t_name]
        if t_range[0] <= dst <= t_range[1]:
          if not printed_src_dst:
            fprint(self.out, "  %d: 0x%X -> 0x%X = " % (c, src, dst))
            printed_src_dst = True
          fprint(self.out, "%d:%s "%(thr['id'], t_name))
          t_range[2] += 1 # count all pointers
          if not (t_range[0] <= src < t_range[1]):
            t_range[3] += 1 # count external pointers

    if printed_src_dst:
      fprint(self.out, "\n")
    
    return printed_src_dst

  def read_value(self, addr, size):
    buf = self.proc.read_memory(addr, size)
    assert(len(buf)==size)
    return int.from_bytes(buf, byteorder='little')

  def search_pointers_in_mem(self,m):
    s = m[0]
    e = m[1]
    p = m[2]
    n = m[3]
    address_size = 8
    
    fprint(self.out, "Searching in memory: 0x%X-0x%X (0x%x) %s %s ..\n" % (s,e,e-s,p,n) )

    start = s
    end = e - 6 # XXX 64 bit # UGLY FIX: prevent reading at the end of the memory region

    counter = 1
    for a in range(start, end, self.step_size):
      try:
        if self.check_target(counter, a, self.read_value(a, address_size)):
          counter += 1
      except gdb.MemoryError:
        # TODO why this error if it is mapped ??
        #fprint(self.out, "  ERR: reading 0x%X gave gdb.MemoryError..\n" % a)
        continue

  def search_pointers(self):
    for m in self.maps:
      self.search_pointers_in_mem(m) 

  def register_targets(self):
    counter = 0
    for t in self.threads:
      counter += 1
      gprint("counter=%d / %d \n"%(counter,len(self.threads)))

      tid = t['id']
      #gprint("T: %d 0x%x\n" % (tid, tid) )
      gexec("thread 0x%x"%tid)
      #gprint("get mem regions\n")
      (stack_addr, stack_size) = get_stack_addr_and_size()
      if g_dbg(): gprint("1: %X-%X\n"%(stack_addr,stack_addr+stack_size))
      (tls_addr, tls_size) = get_tls_addr_and_size()
      if g_dbg(): gprint("2: %X-%X\n"%(tls_addr,tls_addr+tls_size))
      (only_stack_addr, only_stack_size) = get_only_stack_addr_and_size(stack_addr, stack_size, tls_addr)
      if g_dbg(): gprint("3: %X-%X\n"%(only_stack_addr,only_stack_addr+only_stack_size))
      #gprint("get mem regions done\n")
      
      #gprint("set up regions\n")
      # (start, end, num_ptrs, num_ptrs_not_in_start_to_end)
      t['targets']['stack'] = [stack_addr, stack_addr+stack_size, 0, 0]
      t['targets']['tls'] = [tls_addr, tls_addr+tls_size, 0, 0]
      t['targets']['actual_stack'] = [only_stack_addr, only_stack_addr+only_stack_size, 0, 0]
      
      if is_main_thread(stack_addr, stack_size, tls_addr):
        t['targets']['pre_stack'] = [only_stack_addr+only_stack_size, stack_addr+stack_size, 0, 0]
        if g_dbg(): gprint("4: %x-%x\n"%(only_stack_addr+only_stack_size, stack_addr+stack_size))
      #gprint("set up regions done\n")

      if self.most_lower_target_addr > stack_addr:
        self.most_lower_target_addr = stack_addr
      if self.most_lower_target_addr > tls_addr:
        self.most_lower_target_addr = tls_addr
      if self.most_lower_target_addr > only_stack_addr:
        self.most_lower_target_addr = only_stack_addr

      if self.most_upper_target_addr < stack_addr+stack_size:
        self.most_upper_target_addr = stack_addr+stack_size
      if self.most_upper_target_addr < tls_addr+tls_size:
        self.most_upper_target_addr = tls_addr+tls_size
      if self.most_upper_target_addr < only_stack_addr+only_stack_size:
        self.most_upper_target_addr = only_stack_addr+only_stack_size

    #gprint("register_targets done..\n")
      
       
  def init_thread_data_structures(self):
    ts = gdb.selected_inferior().threads()
    gprint("Number of threads: %d\n" % len(ts))
    for t in ts:
      self.threads.append( { 'id':t.num, 'lwpid':t.ptid[1], 'targets':{} } )

  def invoke (self, arg, from_tty):
    # initialize class variables
    self.step_size = 8
    self.threads = []
    self.proc = None
    self.maps = None
    self.most_lower_target_addr = 0xFFFFFFFFFFFFFFFF
    self.most_upper_target_addr = 0
  
    arg = arg.strip()
    if arg == "":
      gprint("Provide a suffix for the output file.\n")
      return
    suffix = arg.split()[0]
    if suffix != arg:
      gprint("Given suffix is invalid: [%s]\n"%suffix)
      return
    
    self.proc = gdb.selected_inferior()
    self.maps = read_maps(self.proc.pid)
    
    # open file: ss_<name>_<pid>-<user_id>.txt
    app_name = get_app_name()
    self.out = open("ss_%s_%d-%s.txt" % (app_name,self.proc.pid,suffix) ,"w") 
    gprint("Writing output to file: %s\n" % self.out.name)
    
    gprint("Initialize the thread data structures..\n")
    self.init_thread_data_structures()

    gprint("Register targets we are interested in..\n")
    self.register_targets()

    gprint("Search for pointers to targets..\n")
    self.search_pointers() 

    gprint("Dump results..\n")
    self.dump_results() 

    gprint("Closing output file..\n")
    self.out.close()
    
    return


FindPointersToTargets()

