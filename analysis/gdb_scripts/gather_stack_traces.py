import os 

p = PEDA()
printing = True #False
debug = False
first_store = set()

#def msg(s):
#  pass
#def warning_msg(s):
#  pass
#def error_msg(s):
#  pass

def pm(m):
  if printing:
    if not m: m = "[m==None]"
    msg("[+] %s" % m)
def dm(m):
  if printing and debug:
    if not m: m = "[m==None]"
    msg("[DEBUG] %s" % m)
def em(m):
  if printing:
    if not m: m = "[m==None]"
    error_msg("[ERROR] %s" % m)

def pexec(cmd):
  dm("exec cmd: %s" % cmd)
  res = p.execute_redirect(cmd)
  dm("exec cmd res: \n<[\n%s\n]>" % res)  
  return res

def proc_running():
  i = pexec("info proc")
  if i == None:
    return False
  if "cmdline = ''" in i:
    return False
  return True

def get_start_end_region(addr):
  # ONLY SEARCHES FOR ADDR in STACK
  pm("looking for stack region that contains addr: 0x%016x"%addr)
  pid = proc_pid()
  if not pid: 
    em("no pid?")
    return
  pid = pid.strip()
  if len(pid.split()) > 1:
    em("multiple pids? %s" % pid)
    return
  
  with open("/proc/%s/maps" % pid,"r") as f:
    dm("opened /proc/%s/maps" % pid)
    for l in f.readlines():
      spl = l.split()[0].split("-")
      start = to_int("0x"+spl[0])
      if start < addr:
        end = to_int("0x"+spl[1])
        if addr < end:
          return (start,end)

  #mappings = pexec("info proc mappings")
  #if not mappings: return (0,0)
  #for m in mappings.split("\n"):
  #  pm(m)
  #  spl = m.split()
  #  start = to_int(spl[0])
  #  pm("%s"%start)
    #if start < addr:
    #  end = to_int(spl[1])
    #  if addr < end:
    #    return (start,end)

#  msg("0x%016x"%addr)
#  for r in p.get_vmmap("stack"):
#    msg("0x%016x - 0x%016x" % (r[0], r[1]) )
#    if r[0] < addr and addr < r[1]:
#      return (r[0], r[1])
#
  return (0,0)

signature = bytes(reversed([0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xC0,0xDE])) # 64bit                    #16.04LTS
#signature = list(reversed(['\xDE','\xAD','\xBE','\xEF','\xDE','\xAD','\xC0','\xDE'])) # 64bit    #12.04LTS
def find_addr_without_signature(stack_addr, rsp):
  found = p.searchmem(stack_addr, rsp, signature) #b'\xde\xad\xbe\xef\xde\xad\xc0\xde')           #16.04LTS
  #found = p.searchmem(stack_addr, rsp, ''.join(signature)) #b'\xde\xad\xbe\xef\xde\xad\xc0\xde') #12.04LTS

  if len(found) == 0: # maybe a new thread was created with empty stack
    return 0

  prev_addr = found[0][0]
  for i in range(1, len(found)):
    curr_addr = found[i][0]
    if curr_addr != prev_addr+8:
      return prev_addr+8

    prev_addr = curr_addr

  return rsp

import struct
def bytes_8_to_int(b, idx):
  return struct.unpack("L", b[idx:idx+8])[0]

import hashlib
def is_first_store():
  cur_thr = pexec("thread")
  if cur_thr in first_store:
    return False
  first_store.add(cur_thr)
  return True  

def store_stack(start, end, rsp):
  if is_first_store():
  #global first_store
  #if first_store:
    #first_store = False
    pm("Skipping the store at first hit of the TOL breakpoint")
    return # skip first hit of the breakpoint

  pm("Storing stack at TOL")
  ##### print until end of stack
  #rsp = end-8
  #####
  non_sign_addr = find_addr_without_signature(start, rsp) 
  if non_sign_addr == 0:
    em("Failed to find a stack location that contains no signature")
    return
  dm("First stack location that has no signature: 0x%x" % non_sign_addr)
  #pm("From top spilled stack loc to rsp distance: %d bytes" % (rsp - non_sign_addr))
  #pm("Distance from top spilled stack loc to stack end: %d bytes" % (rsp - non_sign_addr))

  stack_mem = p.readmem(non_sign_addr, rsp+8-non_sign_addr)

  stack_trace= ""
  for idx in range(0,rsp+1-non_sign_addr, 8):
    stack_trace += "0x%016x\t0x%016x\n" % (non_sign_addr+idx, bytes_8_to_int(stack_mem, idx))
  stack_trace_bytes = stack_trace.encode('utf-8')

  rows = (rsp - non_sign_addr)/8 + 1
  m = hashlib.md5()
  m.update(stack_trace_bytes)
  filename = "%d-%s.txt" % (rows, m.hexdigest())
  filepath = sres + "/" + filename

  if not os.path.isfile(filepath):
    pm("Writing to file: %s" % filename)
    with open(filepath, "wb") as f:
      f.write(pexec("thread").encode('utf-8'))
      f.write(pexec("x/i $rip").encode('utf-8'))
      f.write(stack_trace_bytes)
  else:
    pm("File already exists: %s" % filename)
    

  # TODO add stats of stack trace to the file

def clear_stack(start, end, rsp):
  #pm("Clearing stack at TOL")
  dm("len(signature)=%d" % len(signature))
  num_sign = int((rsp - start) / len(signature))
  p.writemem(start, signature * num_sign)          # 16.04LTS
  #p.writemem(start, ''.join(signature * num_sign)) # 12.04LTS
  dm("clear_stack: written %d bytes starting at 0x%x" % (rsp - start, start))

def process_stack():
  rsp = p.getreg("rsp")
  start = 0
  end = 0
  if rsp:
    (start,end) = get_start_end_region(rsp)
  else:
    rsp = 0

  if start == 0 and end == 0:
    em("clear_stack: could not find memory region of addr 0x%x" % rsp)
    return

  dm("rsp = 0x%x (stack: 0x%x - 0x%x)" % (rsp, start, end))

  store_stack(start, end, rsp)
  clear_stack(start, end, rsp)

  return

def format_regn(regn):
  spl = regn.split("-")
  l = spl[0]
  r = spl[1]
  new_l = ('0' * (16-len(l))) + l
  new_r = ('0' * (16-len(r))) + r

  return "0x"+new_l+" 0x"+new_r

def dump_exec_mem_regions():
  if rres == None or sres == None:
    return

  #pm(pexec("info proc"))
  pid = proc_pid()
  if not pid: 
    em("no pid?")
    return
  pid = pid.strip()
  if len(pid.split()) > 1:
    em("multiple pids? %s" % pid)
    return
  
  exec_mem = ""
  rows = 0
  dm("opening /proc/%s/maps" % pid)
  with open("/proc/%s/maps" % pid,"r") as f:
    dm("opened /proc/%s/maps" % pid)
    for l in f.readlines():
      spl = l.split()
      regn = format_regn(spl[0])
      perm = spl[1]
      name = spl[-1]
      if perm[2] == 'x':
        rows += 1
        exec_mem += "%s %s %s\n" % (regn, perm, name)
  
  #exec_mem = ""
  #rows = 0
  #for r in p.get_vmmap():
  #  if r[2][2] == 'x':
  #    rows += 1
  #    exec_mem += "0x%016x 0x%016x %s %s\n" % (r[0], r[1], r[2], r[3])

  exec_mem_bytes = exec_mem.encode('utf-8')
  m = hashlib.md5()
  m.update(exec_mem_bytes)
  filename = "xmem-%d-%s.txt" % (rows, m.hexdigest())
  filepath = sres + "/" + filename
  if not os.path.isfile(filepath):
    pm("Writing exe dump: %s" % filename)
    with open(filepath, 'wb') as f:
      if rows == 0:
        info_proc = pexec("info proc")
        if info_proc:
          f.write("%s\n" % info_proc)
        else:
          em("No executable memory.. :/ and 'info proc' returns None\n")
          f.write("No executable memory.. :/ and 'info proc' returns None\n")
      else:
        f.write(exec_mem_bytes)
  else:
    pm("Exe dump already exists: %s" % filename)

def httpd_go_to_child_process():
  pexec("set follow-fork-mode child")
  pexec("continue")

  pexec("set follow-fork-mode parent")
  pexec("continue")

  pexec("set follow-fork-mode parent")
  pexec("continue")

  pexec("set follow-fork-mode child")
  pexec("continue")

  
def special_handlers():
  running_exe = p.getfile().split("/")[-1]
  if running_exe.lower().startswith("httpd"):
    httpd_go_to_child_process()
    p.save_user_command("hook-stop")
  elif running_exe.lower().startswith("asterisk"):
    p.save_user_command("hook-stop")

def set_breakpoint_at_tol():
  running_exe = p.getfile().split("/")[-1]
  pm("running exe: %s" % running_exe)
  pexec("set breakpoint pending on")
  if "nginx" in running_exe.lower():
    pexec("break ngx_http_handler")
  elif "lighttpd" in running_exe.lower():
    pexec("break http_request_parse")
  elif running_exe.lower().startswith("httpd"):
    pexec("break ap_process_request")
    pexec("break fork")
  elif "asterisk" in running_exe.lower():
    pexec("break process_message")
    pexec("break ast_cli_command_full")
    pexec("break handle_request_do")
  else:
    pm("Could not set TOL breakpoint for: %s" % running_exe)

def proc_pid():
  infoproc = pexec("info proc")
  
  if not infoproc:
    return None

  if infoproc.strip() == "":
    return None

  return infoproc.split()[1]

rres = None
sres = None
def init_folders():
  global rres
  global sres

  cwd = os.getcwd()
  pid = proc_pid()
  if not pid:
    pm("NO RUNNING PROC ????")
    return
  pm("PID OF RUNNING PROC: [%s]" % pid)
  eres = cwd + "/pirop_eval" + "/"+pid
  rres = eres + "/ret_addr_analysis"
  sres = eres + "/stack_traces" 
  if not os.path.isdir(rres):
    os.makedirs(rres)
  if not os.path.isdir(sres):
    os.makedirs(sres)

def do_stack_gathering():
  pm("start running")
  set_breakpoint_at_tol()
  pexec("run")
  special_handlers()
  init_folders()
  while proc_running():
    dump_exec_mem_regions()
    process_stack()
    pexec("continue")

