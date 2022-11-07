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

class FindGadgetsAroundCodePointer(gdb.Command):
  "Prefix command for saving things."

  def __init__ (self):
    super (FindGadgetsAroundCodePointer, self).__init__ ("find_gadgets_around_code_pointer",
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

  def get_next_insts(self, addr):
    cur_inst = self.p.current_inst(addr)
    if cur_inst[1].startswith("jmp "):
      return [int(cur_inst[1].split()[1],16)]
    
    res = []
    
    next_inst = self.p.next_inst(addr)
    res.append(next_inst[0][0])
    if cur_inst[1][0] == 'j':
      res.append(int(cur_inst[1].split()[1],16))

    return res

  def bad_inst(self,addr):
    inst = self.p.current_inst(addr)
    if inst == None:
      return True

    if not self.p.is_executable(addr):
      return True

    disas = inst[1]
    return ("(bad)" in disas or 
            "internal disassembler error" in disas or
            disas.startswith("call"))

  def find_gadget(self, addr, gadget, visited, glen):
    if glen > 20: 
      return

    if self.bad_inst(addr):
      return

    # check if gadget found
    if self.found_gadget(addr):
      self.dump_gadget(gadget)
      return

    # dont add stopcondition to visited list
    if addr in visited:
      return
    visited.add(addr)

    next_insts = self.get_next_insts(addr)
    if next_insts == None:
      return

    for ni in next_insts:
      gadget.append(ni)
      self.find_gadget(ni, gadget, visited, glen+1)
      gadget.pop()

  def find_gadgets(self,addr):
    self.out.write("Looking for gadgets at 0x%x\n" % addr)

    visited = set()
    gadget = list()
    
    gadget.append(addr)
    self.find_gadget(addr,gadget,visited,1)

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
    #TODO cs => cp (code pointer)
    cp_addr_str = args[0]
    cp_addr = int(cp_addr_str,16)
    if not self.is_callsite(cp_addr):
      gprint("Provided arg is not a callsite address: %s\n" % args[0])
      return
    
    app_name = self.get_app_name()
    mod_name = self.get_mod_name(cp_addr)
    self.out = open("fg_%s_%s_%s.txt" % (app_name,mod_name,cp_addr_str) ,"w") 
    gprint("Writing output to file: %s\n" % self.out.name)

    start_addr = cp_addr - (cp_addr % 0x100) # overwriting 1 byte
    end_addr = start_addr + 0x100 
    self.out.write("Searching for gadgets in the range [0x%x - 0x%x]\n" % (start_addr, end_addr-1))

    for a in range(start_addr, end_addr):
      self.find_gadgets(a)
    #self.find_gadgets(0x00007ffff74c6f5c)

    gprint("Closing output file..\n")
    self.out.close()
    
    return


FindGadgetsAroundCodePointer()

