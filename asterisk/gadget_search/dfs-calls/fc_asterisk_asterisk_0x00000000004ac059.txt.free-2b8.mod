94|43c2b8 call   0x41daa0 <free@plt>
  0 - 4ac059	test   rax,rax
  1 - 4ac05c	je     0x4ac0ca <httpd_helper_thread+506>
  2 - 4ac05e	mov    rdx,r12
  3 - 4ac061	mov    ecx,DWORD PTR [rdx]
  4 - 4ac063	add    rdx,0x4
  5 - 4ac067	lea    eax,[rcx-0x1010101]
  6 - 4ac06d	not    ecx
  7 - 4ac06f	and    eax,ecx
  8 - 4ac071	and    eax,0x80808080
  9 - 4ac076	je     0x4ac061 <httpd_helper_thread+401>
 10 - 4ac078	mov    ecx,eax
 11 - 4ac07a	shr    ecx,0x10
 12 - 4ac07d	test   eax,0x8080
 13 - 4ac082	cmove  eax,ecx
 14 - 4ac085	lea    rcx,[rdx+0x2]
 15 - 4ac089	cmove  rdx,rcx
 16 - 4ac08d	add    al,al
 17 - 4ac08f	mov    rax,r12
 18 - 4ac092	sbb    rdx,0x3
 19 - 4ac096	sub    rdx,r12
 20 - 4ac099	dec    rdx
 21 - 4ac09c	add    rax,rdx
 22 - 4ac09f	jb     0x4ac0c0 <httpd_helper_thread+496>
 23 - 4ac0a1	cmp    BYTE PTR [rsp+rdx*1+0x1040],0x20
 24 - 4ac0a9	jbe    0x4ac0b5 <httpd_helper_thread+485>
 25 - 4ac0ab	jmp    0x4ac0c0 <httpd_helper_thread+496>
 26 - 4ac0c0	cmp    BYTE PTR [rsp+0x1040],0x0
 27 - 4ac0c8	jne    0x4ac108 <httpd_helper_thread+568>
 28 - 4ac0ca	cmp    BYTE PTR [rbx],0x0
 29 - 4ac0cd	jne    0x4ac1e2 <httpd_helper_thread+786>
 30 - 4ac0d3	mov    ecx,0x55e943
 31 - 4ac0d8	mov    edx,0x55e953
 32 - 4ac0dd	mov    esi,0x190
 33 - 4ac0e2	mov    rdi,rbp
 34 - 4ac0e5	call   0x4abcf0 <ast_http_error>
RETURN from call
 35 - 4ac0ea	lock dec DWORD PTR [rip+0x31c873]        # 0x7c8964 <session_count>
 36 - 4ac0f1	test   r13,r13
 37 - 4ac0f4	je     0x4abf10 <httpd_helper_thread+64>
MAY skip
 38 - 4ac0fa	mov    rdi,r13
 39 - 4ac0fd	call   0x474870 <ast_variables_destroy>
 40 - 4ac102	jmp    0x4abf10 <httpd_helper_thread+64>
TILL here
 41 - 4abf10	mov    rdi,QWORD PTR [rbp+0x0]
 42 - 4abf14	test   rdi,rdi
 43 - 4abf17	je     0x4abf1e <httpd_helper_thread+78>
TAKEN
 44 - 4abf1e	mov    esi,0xffffffff
 45 - 4abf23	mov    rdi,rbp
 46 - 4abf26	call   0x43cc10 <__ao2_ref>
ENTER call
 47 - 43cc10	sub    rsp,0x18
 48 - 43cc14	test   rdi,rdi
 49 - 43cc17	je     0x43cc6e <__ao2_ref+94>
NOT taken
 50 - 43cc19	mov    r9d,DWORD PTR [rdi-0x8]
 51 - 43cc1d	lea    rax,[rdi-0x58]
 52 - 43cc21	cmp    r9d,0xa570b123
 53 - 43cc28	je     0x43cc60 <__ao2_ref+80>
TAKEN
 54 - 43cc60	test   rax,rax
 55 - 43cc63	je     0x43cc4f <__ao2_ref+63>
NOT taken
 56 - 43cc65	add    rsp,0x18
 57 - 43cc69	jmp    0x43c1e0 <internal_ao2_ref>
 58 - 43c1e0	mov    QWORD PTR [rsp-0x18],rbx
 59 - 43c1e5	mov    QWORD PTR [rsp-0x10],rbp
 60 - 43c1ea	mov    rbx,rdi
 61 - 43c1ed	mov    QWORD PTR [rsp-0x8],r12
 62 - 43c1f2	sub    rsp,0x28
 63 - 43c1f6	test   rdi,rdi
 64 - 43c1f9	je     0x43c2ef <internal_ao2_ref+271>
NOT taken
 65 - 43c1ff	mov    r9d,DWORD PTR [rdi-0x8]
 66 - 43c203	lea    r12,[rdi-0x58]
 67 - 43c207	cmp    r9d,0xa570b123
 68 - 43c20e	je     0x43c250 <internal_ao2_ref+112>
TAKEN
 69 - 43c250	test   r12,r12
 70 - 43c253	je     0x43c31a <internal_ao2_ref+314>
NOT taken
 71 - 43c259	test   esi,esi
 72 - 43c25b	jne    0x43c268 <internal_ao2_ref+136>
TAKEN
 73 - 43c268	mov    ebp,esi
 74 - 43c26a	lock xadd DWORD PTR [rdi-0x20],ebp
 75 - 43c26f	lea    r9d,[rsi+rbp*1]
 76 - 43c273	cmp    r9d,0x0
 77 - 43c277	jl     0x43c2c8 <internal_ao2_ref+232>
NOT taken
 78 - 43c279	jne    0x43c23a <internal_ao2_ref+90>
NOT taken
 79 - 43c27b	mov    rax,QWORD PTR [rbx-0x18]
 80 - 43c27f	test   rax,rax
 81 - 43c282	je     0x43c289 <internal_ao2_ref+169>
MAY skip
 82 - 43c284	mov    rdi,rbx
 83 - 43c287	call   rax
 84 - 43c289	mov    r8,r12
 85 - 43c28c	mov    ecx,0x542eaa
 86 - 43c291	mov    edx,0x542f90
 87 - 43c296	mov    esi,0x10e
 88 - 43c29b	mov    edi,0x542ea0
 89 - 43c2a0	call   0x4b4bc0 <__ast_pthread_mutex_destroy>
RETURN from call
 90 - 43c2a5	mov    QWORD PTR [rbx-0x58],0x0
 91 - 43c2ad	mov    QWORD PTR [rbx-0x50],0x0
 92 - 43c2b5	mov    rdi,r12
 93 - 43c2b8	call   0x41daa0 <free@plt>
