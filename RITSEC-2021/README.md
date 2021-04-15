# RITSEC 2021 Reversing / Binary Exploitation Challenge Write-ups
The following write-up includes three challenges from RIT's RITSEC CTF 2021 competition.  All three challenges were in the `REV/BIN` category and featured some clever reverse engineering or binary exploitation.  I completed the challenges with OffSec classmate Evan, and certainly could not have progressed through some mental blocks without his ingenuity.     

## Table of Contents
* snek - 100 pts
* Fleshwound - 200 pts
* Baby Graph - 231 pts

### Snek - 100 pts
#### Framing the Challenge
Kicking off the `REV/BIN` category is a challenge called "snek".  All we are given is a `snek` file and the hint "no step on snek" from the author, `~knif3`.  For those unfamiliar, the hint refers to a popular meme with a play on the [Gadsden Flag](https://knowyourmeme.com/memes/gadsden-flag-dont-tread-on-me). 

[!no-step-on-snek](https://knowyourmeme.com/photos/1116586-gadsden-flag-dont-tread-on-me).  

This might not be much of a hint for some players, so the logical next step is to try and identify the file.  Running `file` simply returns `data` which proves that this is not a standard ELF or PE executable.  `strings` reveals some useful information, including `__init__` and `__name__`, which are indicative of a Python file.  Suddenly the hint makes sense!  However this is not a Python `.py` source code file, but rather compiled Python bytecode.  


The next hurdle comes when trying to execute the program.  Depending on the version of Python a contestant has installed, the bytecode may or may not execute.  By luck, my attempt at running with Python3 version 3.9+ failed, but Evan's v3.7 executed it without an error.  This led us to create a Docker container running Python 3.7 instead of trying to revert my Python version.  We set about determining an appropriate disassembler to add to the Dockerfile's installation dependencies and found a suitable candidate, [xdis](https://pypi.org/project/xdis/).  This utility also requires Python's `click`.  These dependencies are installed in the Python 3.7 Docker container using the Dockerfile shown below: 

~~~Docker
FROM python:3.7

run pip install xdis	
run pip install click 
 
user 1000:1000
~~~

The bytecode can now be executed within the container, revealing the prompt `Enter my name: `. Entering a random guess indicates an insuccessful answer and terminates execution.  

~~~shell
❯ python3 snek
Enter my name: comed-ian
WRONG
~~~

Clearly some reverse engineering is required to identify the correct input and tretrieve the flag.

#### Reverse Engineering the Bytecode
As mentioned previously, the `xdis` utility can assist by disassembling the compiled Python bytecode.  `xdis` can be run using a Python script, but also has a convenient CLI extension: `pydisasm`.  Beforehand, the file must be changed to use a `.pyc` extension so the disassembler can process it.  Using `pydisasm snek.pyc` yields a significant amount of metadata which indicates the source is Python 3.7 bytecode, as we established earlier.  Furthermore, the utility disassembles each method.  There are multiple methods recognized, however the key to this challenge exists in the `<module>` and `__init__` methods, which are described below 

##### <module>
The `<module>` method takes care of user interaction and initializing the environment.  It first creates a `d` object of type `'d'`, which is an object with two methods: `__init__` and `__eq__`.  For the sake of brevity, `__eq__` overloads the `==` operator and checks the equivalece of two parameters. The `__init__` method will be discussed in the next section.  `<module>` proceeds to print the problem prompt and accept user input, storing it in `x`.  Lines 28-34 define an object `a` of type `d`, instantiated with `x` as its input (e.g. `a = d(x)`).  Without any further reverse engineering, it is logical to assume that the `d` object performs an encryption / decryption algorithm, as the following command compares equivalence between `a` and `x`.  This is odd, however, as the resulting control flow either prints out `IS_THIS_THE_FLAG??` followed by `NOPE`, or `WRONG`.  It would therefore seem as if feeding the decrypted key into the program does not, in fact, yield the flag.  We next took a look into the `'d'` method, leading to an investigation of the `__init__` method.  

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
As mentioned above, an object created of type `'d'` is instantiated using the `__init__` method.  This method is relatively simple, and contains the info necessary for solving the challenge.  The method only takes two parameters, `self` and `password`, and the `password` input is first encoded into bytes, assuming a string input.  Next, a 77 byte list is created using a number of defined constants and stored in the member variable `self.decrypt`.  It is also noted that the `__eq__` method uses this `self.decrypt` variable for equivalence checking against an input string.  Furthermore, the loaded bytes appear to be ASCII letter values.  Therefore it is logical to assume that this string either is our key or contains our key.  

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

#### Decrypting the Key
A simple Python file was created to output the presumed ASCII values as characters.  

~~~python
#!/usr/bin/python3
key = [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 95, 82, 83, 123, 97, 108, 108, 95, 104, 105, 36, 36, 95, 97, 110, 100, 95, 110, 48, 95, 98, 105, 116, 51, 125]


for k in key: 
    print(chr(k), end="")
~~~

The result was the string: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_RS{all_hi$$_and_n0_bit3}`, which clearly contains the RITSEC flag prefix at the end!  Now it makes sense why the program only printed out negative feedback, because the flag was present in ASCII form the entire time. 

### Fleshwound
