62|4731be call   0x41daa0 <free@plt>
  0 - 4ac059	test   rax,rax
  1 - 4ac05c	je     0x4ac0ca <httpd_helper_thread+506>
(-26)
TAKEN
 28 - 4ac0ca	cmp    BYTE PTR [rbx],0x0
 29 - 4ac0cd	jne    0x4ac1e2 <httpd_helper_thread+786>
not taken
 30 - 4ac0d3	mov    ecx,0x55e943
 31 - 4ac0d8	mov    edx,0x55e953
 32 - 4ac0dd	mov    esi,0x190
 33 - 4ac0e2	mov    rdi,rbp
 34 - 4ac0e5	call   0x4abcf0 <ast_http_error>
RETURN from call
 35 - 4ac0ea	lock dec DWORD PTR [rip+0x31c873]        # 0x7c8964 <session_count>
 36 - 4ac0f1	test   r13,r13
 37 - 4ac0f4	je     0x4abf10 <httpd_helper_thread+64>
not taken
 38 - 4ac0fa	mov    rdi,r13
 39 - 4ac0fd	call   0x474870 <ast_variables_destroy>
ENTER call
 40 - 474870	test   rdi,rdi
 41 - 474873	push   rbx
 42 - 474874	jne    0x47487b <ast_variables_destroy+11>
TAKEN
 43 - 47487b	mov    rbx,QWORD PTR [rdi+0x10]
 44 - 47487f	call   0x4731e0 <ast_variable_destroy>
ENTER call
 45 - 4731e0	push   rbx
 46 - 4731e1	mov    rbx,rdi
 47 - 4731e4	lea    rdi,[rdi+0x30]
 48 - 4731e8	call   0x4731a0 <ast_comment_destroy>
-4
ENTER call
 53 - 4731a0	push   rbp
 54 - 4731a1	mov    rbp,rdi
 55 - 4731a4	push   rbx
 56 - 4731a5	sub    rsp,0x8
 57 - 4731a9	mov    rdi,QWORD PTR [rdi]
 58 - 4731ac	test   rdi,rdi
 59 - 4731af	jne    0x4731bb <ast_comment_destroy+27>
TAKEN
 60 - 4731bb	mov    rbx,QWORD PTR [rdi]
 61 - 4731be	call   0x41daa0 <free@plt>
