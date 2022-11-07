#from __future__ import with_statement
#from __future__ import print_function
import gdb
from time import sleep

# TODO low prior: at every command dump it to a new directory, optional..
# get exact tls start and end address for secondary threads and main-thread
# get exact stack start and end address for secondary threads and main-thread

def g_dbg():
  return 0

def gexec(s):
  gdb.execute(s)

def geval(s):
  return gdb.parse_and_eval(s)

def gprint(s):
  gdb.write(s)

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
  
def get_only_stack_addr_and_size(stack_addr, stack_size, tls_addr):
  only_stack_start = stack_addr

  if stack_addr <= tls_addr < stack_addr+stack_size:
    # we are in secondary thread
    only_stack_end = tls_addr  
  else:
    # we are in main_thread
    only_stack_end = get_value_eval("__libc_stack_end")
  
  return (only_stack_start, only_stack_end - only_stack_start)

class PointerAnalysis(gdb.Command):
  "Prefix command for saving things."

  def __init__ (self):
    super (PointerAnalysis, self).__init__ ("ss_pointer_analysis",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE)

  def invoke (self, arg, from_tty):
    (stack_addr, stack_size) = get_stack_addr_and_size()
    (tls_addr, tls_size) = get_tls_addr_and_size()
    (only_stack_addr, only_stack_size) = get_only_stack_addr_and_size(stack_addr, stack_size, tls_addr)
  
    gprint("stack_addr (+size) = 0x%X (+0x%x)\n" % (stack_addr, stack_size) )
    gprint("tls_addr (+size) = 0x%X (+0x%x)\n" % (tls_addr, tls_size) )
    gprint("only_stack_addr (+size) = 0x%X (+0x%x)\n" % (only_stack_addr, only_stack_size) )

    gprint("save pointers to stack to [ptr_to_stack-%s]\n" % arg)
    gexec("find_pointers -t 0x%x 0x%x -o ptr_to_stack-%s" % (stack_addr,stack_addr+stack_size,arg) )
    gprint("save pointers to stack to [ptr_to_tls-%s]\n" % arg)
    gexec("find_pointers -t 0x%x 0x%x -o ptr_to_tls-%s" % (tls_addr,tls_addr+tls_size,arg) )
    gprint("save ONLY pointers to stack to [ptr_to_only_stack-%s]\n" % arg)
    gexec("find_pointers -t 0x%x 0x%x -d -o ptr_to_only_stack-%s" % 
                (only_stack_addr, only_stack_addr+only_stack_size, arg) )

    gprint("done saving pointers\n")
    


PointerAnalysis()
