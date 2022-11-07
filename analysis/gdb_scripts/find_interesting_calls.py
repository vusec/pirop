import gdb
from time import sleep

def fprint(f,s):
  f.write(s)
  f.flush()

def g_dbg():
  return 0

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

class FindInterestingCalls(gdb.Command):
  "Prefix command for saving things."

  def __init__ (self):
    super (FindInterestingCalls, self).__init__ ("find_interesting_calls",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE)

  # find gadgets around return addresses in backtrace
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

  def read_value(self, addr, size):
    buf = self.proc.read_memory(addr, size)
    assert(len(buf)==size)
    return int.from_bytes(buf, byteorder='little')

  def found_gadget(self, addr):
    inst = self.p.current_inst(addr)
    disas = inst[1]

    if disas == "ret" or disas.startswith("ret "):
      #assert(disas == "ret")
      return True

    if disas.startswith("jmp") and not disas.startswith("jmp    0x"):
      return True

    return False

  def dump_gadget(self, gadget):
    # gadget length
    gstr = "%d|" % len(gadget)
    
    # gadget type
    inst = self.p.current_inst(gadget[-1])
    if inst[1] == "ret" or inst[1].startswith("ret "):
      gstr += "r|"
    else:
      gstr += "j|"

    # gadget instructions
    for addr in gadget:
      inst = self.p.current_inst(addr)
      gstr += "\n0x%x\t%s" % (inst[0],inst[1])
      #gstr += "0x%x\t%s|" % (inst[0],inst[1])
    #gstr = gstr[:-1] # remove the last pipe character

    # write to file
    self.out.write("%s\n" % gstr)

  def get_next_insts(self, addr, call_stack):
    # TODO also handle calls
    cur_inst = self.p.current_inst(addr)

    if cur_inst[1].startswith("jmp    0x"):
      return [int(cur_inst[1].split()[1],16)]

    #if cur_inst[1].startswith("call"):
    #  if not cur_inst[1].startswith("call   QWORD"):
    #    next_inst = self.p.next_inst(addr)
    #    call_stack.append(next_inst)
    
    if cur_inst[1].startswith("ret"):
      return None
    #  if len(call_stack) == 0:
    #    return None
    #  return call_stack.pop()
    
    res = []
    
    next_inst = self.p.next_inst(addr)
    res.append(next_inst[0][0])
    if cur_inst[1][0] == 'j' and not cur_inst[1].startswith("jmp"):
      res.append(int(cur_inst[1].split()[1],16))

    if cur_inst[1].startswith("call   0x"):
      if cur_inst[1].endswith("@plt>"): return None
      res.append(int(cur_inst[1].split()[1],16))

    return res

  def bad_inst(self,addr):
    inst = self.p.current_inst(addr)
    if inst == None:
      return True

    if not self.p.is_executable(addr):
      return True

    disas = inst[1]
    if ("(bad)" in disas or 
            "internal disassembler error" in disas or
            "hlt" == disas or
            "add    BYTE PTR [rax],al" == disas ):
      
      print ("[X] %x - bad instr:"%addr), disas
      return True
    return False

  def check_for_interesting_instruction(self,addr,gadget):
    inst = self.p.current_inst(addr)
    disas = inst[1]

    #print ("at addr 0x%x" % addr), "* disas:", disas

    if disas.startswith("call") and disas.endswith("@plt>"):
      #print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX %d|%x %s" % (len(gadget),addr, disas)
      self.out.write("%d|%x %s\n" % (len(gadget),addr, disas))
      if "alloc" in disas or "free" in disas:
        for i in range(len(gadget)):
          self.out.write("%3d - %x\t%s\n" % (i, gadget[i], self.p.current_inst(gadget[i])[1]) )

  def find_gadget(self, addr, gadget, visited, glen, call_stack):
    #if glen > 20: 
    #  return

    # dont add stopcondition to visited list
    if addr in visited:
      return
    visited.add(addr)

    if self.bad_inst(addr):
      return

    self.check_for_interesting_instruction(addr,gadget)

    next_insts = self.get_next_insts(addr,call_stack)
    #print "next instructions: "
    #if next_insts:
    #  for i in next_insts:
    #    print "- 0x%x" % i
    #else:
    #  print "- None"

    if next_insts == None:
      return

    for ni in next_insts:
      gadget.append(ni)
      self.find_gadget(ni, gadget, visited, glen+1, call_stack)
      gadget.pop()

  def find_gadgets(self,addr):
    self.out.write("Looking for gadgets at 0x%x\n" % addr)

    visited = set()
    gadget = list()
    call_stack = list()
    
    gadget.append(addr)
    self.find_gadget(addr,gadget,visited,1,call_stack)

  def get_next_insts_bfs(self, addr):
    cur_inst = self.p.current_inst(addr)

    if cur_inst[1].startswith("jmp    0x"):
      return [int(cur_inst[1].split()[1],16)]
    
    if cur_inst[1].startswith("ret"):
      return None

    res = []
    
    next_inst = self.p.next_inst(addr)
    res.append(next_inst[0][0])
    if cur_inst[1][0] == 'j' and not cur_inst[1].startswith("jmp"):
      res.append(int(cur_inst[1].split()[1],16))

    if cur_inst[1].startswith("call   0x"):
      if cur_inst[1].endswith("@plt>"): return None
      res.append(int(cur_inst[1].split()[1],16))

    return res

  def check_for_interesting_instruction_bfs(self,addr,glen):
    inst = self.p.current_inst(addr)
    disas = inst[1]

    if disas.startswith("call") and disas.endswith("@plt>"):
      self.out.write("%d|%x %s\n" % (glen, addr, disas))

  def find_gadgets_bfs(self, addr):
    glen = 1
    ins_to_visit = []
    ins_to_visit.append(addr)
    next_ins_to_visit = []
    visited = set()

    while len(ins_to_visit) > 0:
      addr = ins_to_visit.pop(0)
      visited.add(addr)

      if not self.check_for_interesting_instruction_bfs(addr, glen):
        next_insts = self.get_next_insts_bfs(addr)
        if next_insts:
          for ni in next_insts:
            if ni not in visited:
              next_ins_to_visit.append(ni)
      
      if len(ins_to_visit) == 0:
        ins_to_visit = next_ins_to_visit
        next_ins_to_visit = []
        glen += 1


  def get_app_name(self):
    return gdb.current_progspace().filename.split('/')[-1]

  def get_mod_name(self, addr):
    assert(isinstance(addr,int) or isinstance(addr,long))

    for m in self.maps:
      if m[0] <= addr < m[1]:
        return m[3].split("/")[-1].split(".")[0].split("-")[0]

    return "NO_MOD_NAME"

  def is_callsite(self, addr):
    assert(isinstance(addr,int) or isinstance(addr,long))

    return self.p.is_executable(addr)
    
    #ins = self.p.prev_inst(addr)
    #if ins == None: return False
    #return ins[0][1].startswith("call ") or ins[0][1].startswith("\tcall ")

  def invoke (self, arg, from_tty):
    # initialize class variables
    gdb.execute("set width 300")
    self.p = PEDA()
    self.proc = gdb.selected_inferior()
    self.maps = self.p.get_vmmap()
  
    args = arg.strip().split()
    #gprint("arg=[%s]\n" % args)
    if len(args) != 1:
      gprint("Provide a callsite address.\n")
      return
    cp_addr_str = args[0]
    cp_addr = int(cp_addr_str,16)
    if not self.is_callsite(cp_addr):
      gprint("Provided arg is not a callsite address: %s\n" % args[0])
      return
    
    app_name = self.get_app_name()
    mod_name = self.get_mod_name(cp_addr)
    self.out = open("fc_%s_%s_%s.txt" % (app_name,mod_name,cp_addr_str) ,"w") 
    gprint("Writing output to file: %s\n" % self.out.name)

    self.out.write("Searching for gadgets with calls into plt \n")

    self.find_gadgets_bfs(cp_addr)

    gprint("Closing output file..\n")
    self.out.close()
    
    return


FindInterestingCalls()

