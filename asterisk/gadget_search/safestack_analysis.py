#from __future__ import with_statement
#from __future__ import print_function
import gdb
from time import sleep

def gexec(s):
  #sleep(0.7)
  gdb.execute(s)

class SafeStackTwoThreads(gdb.Command):
  "Prefix command for saving things."

  def __init__ (self):
    super (SafeStackTwoThreads, self).__init__ ("ss_two_threads_stats",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE)

  def my_print(self,s):
    gdb.write(s)
      
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
    # TODO: -a(ddr) 0x123 -l(ength) 0x345

    self.target_exact       = False
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
        if self.target_space_start == self.target_space_end:
          self.target_exact = True
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
        
    if self.target_space_end == 0:
      return False

    return True


  def in_target(self,t):
    if self.target_exact:
      return self.target_space_start == t
    
    return self.target_space_start <= t < self.target_space_end


  def search_pointers_in_mem(self,proc,m):
    s = m[0]
    e = m[1]
    p = m[2]
    n = m[3]
    
    self.my_print( "Searching in memory: 0x%X-0x%X %s %s ..\n" % (s,e,p,n) )

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
    for a in range(start,end, 8 ):
      try:
        t = self.read_value(a, proc, 8)
        if self.in_target(t):
          counter += 1
          self.my_print("  %d: 0x%X -> 0x%X\n" % (counter, a, t))
      except gdb.MemoryError:
        continue

  def get_region(self,addr):
    for m in self.maps:
      s = m[0]
      e = m[1]
      if s <= addr < e:
        return (s,e)

    raise gdb.GdbError("Could not find a mapped memory region that contains: [0x%X]" % addr)
    return (0,0)
      

  def get_stack_region_main(self):
    # assuming we are in main-thread(1)
    stack_addr = int("%s"%gdb.parse_and_eval("$rsp"),16)
    return self.get_region(stack_addr)

  def get_tls_region_main(self):
    # assuming we are in main-thread(1)
    gexec("call arch_prctl (0x1003, $rsp-8)")
    tls_addr = int("%s"%gdb.parse_and_eval("{long}($rsp-8)"),16)  #x/gx $rsp-8"),16)
    gexec("set {long}($rsp-8)=0xDEADBEEF")
    return self.get_region(tls_addr)


  def get_stack_region_thread(self):
    stack_addr = int("%s"%gdb.parse_and_eval("$rsp"),16)
    (s,e) = self.get_region(stack_addr)
    return (s,e-0x10C0)
    
  def get_tls_region_thread(self):
    stack_addr = int("%s"%gdb.parse_and_eval("$rsp"),16)
    (s,e) = self.get_region(stack_addr)
    return (e-0x10C0,e)
    

  def get_stack_and_tls_regions(self,prog,pid):
    self.read_maps(pid)

    stack_start = 0
    stack_end = 0
    tls_start = 0
    tls_end = 0
    if prog == "main":
      (stack_start, stack_end) = self.get_stack_region_main()
      (tls_start, tls_end) = self.get_tls_region_main()
    elif prog == "thread":
      (stack_start, stack_end) = self.get_stack_region_thread()
      (tls_start, tls_end) = self.get_tls_region_thread()

    return (stack_start, stack_end, tls_start, tls_end)
      

  def exec_find_pointers(self,s,e,o):
    self.find_ptr_counter += 1
    #if self.find_ptr_counter <= 16:
    #  return
    gdb.write(" - -- --- -- -- -- --- -- -- -- -- - -- --          EXEC_FIND_POINTERS\n")
    gexec( "find_pointers -t 0x%x 0x%x -d -o ptr_to_%d-%s.txt" % (s,e, self.find_ptr_counter ,o) )
    gdb.write(" - -- --- -- -- -- --- -- -- -- -- - -- --          EXEC_FIND_POINTERS    --   DONE\n")
    

  def invoke (self, arg, from_tty):
    self.find_ptr_counter = 0

    # start and config app
    gexec("enablerandom")
    gexec("start")
    gexec("enablelocking")

    # get process
    proc = gdb.selected_inferior()
    #procs = gdb.inferiors()
    #assert(len(procs)==1)
    #proc = procs[0]
    
    # set breakpoints
    gexec("break main")
    gexec("break pthread_create")
    gexec("break pthread_join")
    gexec("break my_start_thread")

    #gather stats start
    # stack/tls region clear
    (stack_main_start, stack_main_end, tls_main_start, tls_main_end) = self.get_stack_and_tls_regions("main",proc.pid)
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-at_start")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-at_start")

    gexec("c")
    # main-thread(1) stops at breakpoint: main
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-at_main")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-at_main")

    gexec("c")
    gexec("c")
    # main-thread(1) stops at breakpoint: pthread_create <- about to create second thread
    gexec("c")
    # second thread created
    # main-thread(1) stops at breakpoint: pthread_create <- about to create third thread
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-created_thread_2")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-created_thread_2")
    gexec("c")

    gexec("thread 2")
    # thread 2 got just created
    (thread_2_stack_start, thread_2_stack_end, thread_2_tls_start, thread_2_tls_end) = self.get_stack_and_tls_regions("thread",proc.pid)
    self.exec_find_pointers(thread_2_stack_start, thread_2_stack_end, "stack_thread_2-at_clone")
    self.exec_find_pointers(thread_2_tls_start, thread_2_tls_end, "tls_thread_2-at_clone")
    
    gexec("thread 1")
    gexec("c")
    # third thread created
    # main-thread(1) stops at breakpoint: pthread_join
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-created_thread_3")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-created_thread_3")

    gexec("thread 3")
    # thread 3 got just created
    (thread_3_stack_start, thread_3_stack_end, thread_3_tls_start, thread_3_tls_end) = self.get_stack_and_tls_regions("thread",proc.pid)
    self.exec_find_pointers(thread_3_stack_start, thread_3_stack_end, "stack_thread_3-at_clone")
    self.exec_find_pointers(thread_3_tls_start, thread_3_tls_end, "tls_thread_3-at_clone")
    
    gexec("thread 2")
    gexec("c")
    # thread 2 stops at breakpoint: my_start_thread
    self.exec_find_pointers(thread_2_stack_start, thread_2_stack_end, "stack_thread_2-at_my_start")
    self.exec_find_pointers(thread_2_tls_start, thread_2_tls_end, "tls_thread_2-at_my_start")

    gexec("thread 3")
    gexec("c")
    # thread 3 stops at breakpoint: my_start_thread
    self.exec_find_pointers(thread_3_stack_start, thread_3_stack_end, "stack_thread_3-at_my_start")
    self.exec_find_pointers(thread_3_tls_start, thread_3_tls_end, "tls_thread_3-at_my_start")
    
    gexec("thread 2")
    gexec("c")
    # thread 2 finishes
    gexec("thread 1")
    self.exec_find_pointers(thread_2_stack_start, thread_2_stack_end, "stack_thread_2-finished")
    self.exec_find_pointers(thread_2_tls_start, thread_2_tls_end, "tls_thread_2-finished")
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-thread_2_finished")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-thread_2_finished")
    
    gexec("thread 3")
    gexec("c")
    # thread 3 finishes
    gexec("thread 1")
    self.exec_find_pointers(thread_3_stack_start, thread_3_stack_end, "stack_thread_3-finished")
    self.exec_find_pointers(thread_3_tls_start, thread_3_tls_end, "tls_thread_3-finished")
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-thread_3_finished")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-thread_3_finished")

    gexec("thread 1")
    gexec("c")
    # main-thread(1) stops at breakpoint: pthread_join (for third thread)
    # main-thread(1) clears second thread
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-cleared_thread_2")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-cleared_thread_2")

    gexec("break exit")
    gexec("c")
    # main-thread(1) stopts at breakpoint: exit
    # main-thread(1) clears third thread
    self.exec_find_pointers(stack_main_start, stack_main_end, "stack_main-cleared_thread_3")
    self.exec_find_pointers(tls_main_start, tls_main_end, "tls_main-cleared_thread_3")
    
    gexec("c")
    # app is done executing
    # XXX SHOULD BE DONE .. else c c c  





SafeStackTwoThreads()
