#!/usr/bin/python3
from pwn import *
# b1NaRy_S34rch1nG_1s_3asy_p3asy

def binary_connect():
  p = remote('pwnable.kr', 9007)
  return p

def exploit(): 
  def get_result():
    resp = p.recvline()
    if resp[0:8] == b"Correct!":
      return 1
    return resp

  def get_results(start, mid):
    resp = p.recvline()
    if resp[:8] == b"Correct!":
      print(resp)
      return 9
    w = int(resp.strip())
    if w == 9:
      p.send(str(start).encode("utf-8") + b'\n')
      resp = p.recvline()
      while(resp[0:8] != b"Correct!"):
        p.send(str(start).encode("utf-8") + b'\n')
        resp = p.recvline()
      print(resp)
      return 9
    if w < (mid - start) * 10:
      return 1
    else:
      return 0

  def solve(n, c):
    # pause()
    start = 0
    end = n
    mid = n // 2
    while True:
      query = b""
      for num in range(start, mid):
        query += str(num).encode("utf-8") + b" "
      query = query[:-1] + b'\n'
      p.send(query)
      res = get_results(start, mid)
      if res == 9:
        break
      if res == 1:
        end = mid
        mid = (end-start) // 2 + start
      else:
        start = mid
        mid = (end - start) // 2 + start
        if mid == start: # handle last edge case
          mid += 1
      # print(start, mid, end)


  # exploit starts here 
  p = binary_connect()
  p.recvuntil("3 sec... -\n\t\n")
  time.sleep(3.5)
  while True:
    line = p.recvline().decode("utf-8")
    try:
      n = int(line.split(" ")[0].split("=")[1])
      c = int(line.split(" ")[1].split("=")[1])
    except:
      print(line)
    solve(n, c)

if __name__ == "__main__":
  # context.log_level="debug"
  exploit()