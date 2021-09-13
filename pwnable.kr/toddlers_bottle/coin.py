#!/usr/bin/python3
from pwn import *

LOCAL = False
DEBUG = False

def binary_connect():
  p = remote('pwnable.kr', 9007)
  return p

def exploit(): 
  def get_results(count):
    resp = p.recvline()
    # print(resp)
    if resp[:8] == b"Correct!":
      return 10
    w = int(resp.strip())
    # print("w: " + str(w))
    if w == 9:
      return 9
    if w < count * 10:
      return 1
    else:
      return 0

  def solve(n, c):
    # pause()
    i = 1
    start = 0
    end = n
    mid = n // 2
    while True:
      query = b""
      for num in range(start, mid):
        query += str(num).encode("utf-8") + b" "
      query = query[:-1] + b'\n'
      # print(b"query: " + query)
      p.send(query)
      # print("sending " + str(mid - start) + " count ")
      res = get_results(mid - start)
      # print("results: " + str(res))
      if res == 10:
        break
      if res == 9:
        p.send(str(start).encode("utf-8") + b'\n')
        resp = p.recvline()
        if resp[:8] == b"Correct!":
          print(resp)
          break
        else:
          p.send(str(start).encode("utf-8") + b'\n')
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
  time.sleep(4)
  while True:
    line = p.recvline().decode("utf-8")
    n = int(line.split(" ")[0].split("=")[1])
    c = int(line.split(" ")[1].split("=")[1])
    # print(n, c)
    solve(n, c)

if __name__ == "__main__":
  # context.log_level="debug"
  exploit()