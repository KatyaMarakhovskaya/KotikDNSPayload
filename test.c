#include<stdio.h>
#include<string.h>

const char shellcode[] = "\0x00\YOUR\SHELL\CODE\0x00\"; 





int main(){
    int (*ret)() = (int(*)())shellcode;
    ret();
}

