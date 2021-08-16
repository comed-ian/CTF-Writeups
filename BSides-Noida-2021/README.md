# BSides Noida CTF 2021 Binary Exploitation Challenge Write-ups

The following write-up includes two challenges from BSide's Noida CTF 2021 competition. 

## Table of Contents
* Baby Stack - 472 pts
* Warmup - 494 pts

## Baby Stack
tbc.

## Warmup
### Finding the Bug
This challenge is another standard ELF x86-64bit executable exploitation which allows the user to store entries interactively. Unfortunately the binary is stripped of symbols, making reversing and debugging a bit more challenging.  Running the executable shows an interactive menu that allows multiple options, all which seem familiar in a CTF challenge:

```bash
=1= add
=2= show
=3= edit
=4= del
=5= save
=6= exit
> 
```

Browsing through disassembly indicates that there are a total of 16 indices available for storage, from 0-15. The search for the program's bug started by examining the multiple calls to `malloc` and `free`, since the input strings are stored dynamically on the heap. The first function of interest is the `save` option, which seems a bit redundant since the strings are all stored into memory by the `add` function. Decompilation shows that the save function takes a input index and stores it in `curr_index` if not already set to a valid storage index.  The `curr_index` value (an arbitrary variable name based on my analysis) is initially set to -1, so this function can only be used once in the program. Odd, but not individually useful.

```c
void save(void)

{
  long in_FS_OFFSET;
  int index_choice;
  long stack_canary;
  
  stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  index_choice = 0;
  printf("idx: ");
  __isoc99_scanf(&%d,&index_choice);
  getchar();
  if (((-1 < index_choice) && (index_choice < 0x10)) && (curr_index == -1)) {
    curr_index = index_choice;
  }
  if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Browsing the `delete` function reveals the utility of `save`. Decompilation shows that the program interacts as expected...for some cases. If provided a valid index and a pointer at that index exists, then it is freed.  However, there is another conditional statement that begs further investigation: `if (input_index == curr_index) uaf_flag = 1;`.  If this condition is met, the array index is freed and a flag is set to 1, but the array index is *not* cleared, leading to a use after free vulnerability.  The flag prevents this condition from occurring again which restricts the user to a single UAF with which to work. This is still powerful, and enough to solve the challenge.

```c
void delete(void)

{
  long in_FS_OFFSET;
  int input_index;
  long stack_canary;
  
  stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  input_index = 0;
  printf("idx: ");
  __isoc99_scanf(&%d,&input_index);
  getchar();
  if ((-1 < input_index) && (input_index < 0x10)) {
    if (*(long *)(&strings_array + (long)input_index * 8) != 0) {
      if ((input_index == curr_index) && (uaf_flag != 0)) goto fail;
      free(*(void **)(&strings_array + (long)input_index * 8));
    }
    if (input_index == curr_index) {
      uaf_flag = 1;
    }
    else {
      *(undefined8 *)(&strings_array + (long)input_index * 8) = 0;
    }
  }
fail:
  if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

### Leaking Addresses 
The key to this UAF is that the other menu options are still available to the corresponding index even after its pointer has been freed. This means that the `show` function will still print any data available at the residual pointer location; this can be used to leak a heap address if the freed chunk resides in fastbins (so long as it is the second or later entry in the bin) or a `main_arena` address if the chunk is located in the unsorted bin.  A heap address leak is included in the solution file, though it was not used for the exploit. Rather, the `main_arena` address was prioritized because none of the storage indices contain function pointers that can be corrupted to hijack execution flow.  Instead, leaking a `main_arena` address can set up a `__free_hook` or  `__malloc_hook` corruption when either function is called.  Since user input controls invokes calls to `malloc` and `free`, this makes the most sense.  

The process is as follows:
* allocate a couple (in this case, 3) chunks of the same target size. The first of these will be the UAF chunk.  These chunks will be referred to as “the Big Three”
* allocate and free seven chunks of the target size to fill tcache
* free the second and third chunks of the Big Three to push their chunks into fastbins
* save and free the first chunk, which is also the chunk at the lowest memory address on the heap.  This yields a UAF for this first chunk.  Currently, its `fw` pointer will point to the most recently freed chunk, since it is in fastbins
* consolidate the heap by allocating (and subsequently freeing) a large chunk.  Consolidation will keep the tcache chunks, which form a barrier between the top chunk and the Big Three.  The Big Three will be consolidated into a single chunk and pushed into the unsorted bin.  Now, the UAF chunk’s `fw` pointer is set to an index in `main_arena`
* `show` the UAF chunk, leaking the `main_arena` address for this unsorted bin size

### Determining a Target for UAF
Choosing the target size depends on the next step of the exploit, which is allocating an nearly arbitrary pointer.  Because the UAF chunk still has write capabilities through the `edit` function, the chunk’s `fw` pointer can be manipulated accordingly.  Having the chunk in unsorted bins is not useful for the overwrite, because changing the `fw` pointer now would just corrupt the unsorted bin’s link list and crash the program.  However, if the UAF chunk finds its way back into fastbins, which is a singly linked list, the `fw` pointer can be overwritten without crashing.  To coerce the chunk back into fastbins, the steps are simply:

* empty tcache by allocating seven target size chunks
* allocate another target chunk size chunk, which will be pulled from the unsorted bins now that tcache is empty. This will overlap with the UAF chunk and pull it out of the unsorted bin
* fill tcache by freeing seven other target size chunks
* free the overlapping chunk, so the UAF chunk (the first of the Big Three) is now in fastbins

Now that the chunk is in fastbins, editing the index will edit the freed chunk’s `fw` pointer, giving arbitrary `malloc` potential.  This still hasn’t solved the target size problem, as that depends on *where* the target chunk is allocated.  To pass the fastbins `malloc` checks, the allocated pointer needs to have a legitimate size in its `ptr – 0x08` qword.  Poking around `__free_hook` does not reveal any potential targets, however there is data above `__malloc_hook`.  Reorienting the memory dump to start 0x33 bytes prior to main arena show a chunk that has a “size” value in the previous qword equal to 0x7f.  That means it can pass a `malloc` call so long as its chunk address is in the 0x70 fastbin.  Thankfully, the `PREV_INUSE`, `IS_MMAPPED` and `NON_MAIN_ARENA` bits are ignored by the fastbins `malloc` call.  Furthermore, the first qword of the allocated chunk (which corresponds to the `fw` pointer of a freed chunk) is 0x0, meaning that fastbins will not link an invalid memory address as the “next” pointer in the linked list.  

```gdb
gef➤  x/40xg (&__malloc_hook)-0x8
0x7f0882e61b30 <_IO_wide_data_0+208>:	0x0000000000000000	0x0000000000000000
0x7f0882e61b40 <_IO_wide_data_0+224>:	0x00007f0882e62f60	0x0000000000000000
0x7f0882e61b50:	0x0000000000000000	0x0000000000000000
0x7f0882e61b60 <__memalign_hook>:	0x00007f0882d13570	0x00007f0882d13bf0
0x7f0882e61b70 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
0x7f0882e61b80 <main_arena>:	0x0000000000000000	0x0000000000000001
0x7f0882e61b90 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7f0882e61ba0 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7f0882e61bb0 <main_arena+48>:	0x0000000000000000	0x0000556f5f77a290

gef➤  x/20 0x7f0882e61b80-0x33-0x8
0x7f0882e61b45 <_IO_wide_data_0+229>:	0x000000000000007f		0x0000000000000000
0x7f0882e61b55:	0x0000000000000000	0x0882d13570000000
0x7f0882e61b65 <__memalign_hook+5>:	0x0882d13bf000007f		0x000000000000007f
0x7f0882e61b75 <__malloc_hook+5>:	0x0000000000000000	0x0000000000000000
0x7f0882e61b85 <main_arena+5>:	0x0000000001000000	0x0000000000000000
```

Therefore, the target size is now 0x70 (which requires an allocation between 0x59 and 0x68 bytes), and the “faked” chunk pointer to be stored in the UAF `fw` pointer is 0x10 bytes before the first byte to be written, meaning it is 0x43 before `main_arena` or 0x33 before `__malloc_hook`.  With this information, the next steps in the exploit are: 

* write the UAF chunk with seven bytes (to avoid the trailing null which is stored by the augmented read function) corresponding to the address of `main_arena – 0x43` to set up a fake freed chunk in the linked list
* empty tcache by allocating seven 0x70 chunks (with~0x60 bytes of data)
* allocate another chunk to set up the next `malloc` call to return the faked chunk

### Controlling RIP
Now that the next 0x70 allocation returns the faked chunk, the data allocated needs to overwrite `__malloc_hook` to a suitable address.  Since there is no current control of the stack, a long rop chain is likely unsuitable. But, the challenges provides the libc binary which can be searched for any `execve(‘/bin/sh’,…)`and “one gadgets” that precede it. An easy way to identify these is the [one_gadget utility](https://github.com/david942j/one_gadget), which returns the following results:

```bash
❯ one_gadget libc.so.6          
0xdf54c execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xdf54f execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xdf552 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

These are some tough constraints, especially given `__malloc_hook` is called from within `malloc` and thus control is limited.  Pausing the binary prior to the `__malloc_hook` call shows the following register states: 

```gdb
gef➤  i r
rax            0x7f9d5c4ccc81      0x7f9d5c4ccc81
rbx            0x7                 0x7
rcx            0x0                 0x0
rdx            0x0                 0x0
rsi            0x5563266763ba      0x5563266763ba
rdi            0x0                 0x0
rbp            0x7ffcaf494a60      0x7ffcaf494a60
rsp            0x7ffcaf494a38      0x7ffcaf494a38
r8             0x6                 0x6
r9             0x6                 0x6
r10            0x556326677046      0x556326677046
r11            0x246               0x246
r12            0x556326676160      0x556326676160
r13            0x7ffcaf494b70      0x7ffcaf494b70
r14            0x0                 0x0
r15            0x0                 0x0
rip            0x7f9d5c4833d9      0x7f9d5c4833d9 <__GI___libc_malloc+377>
eflags         0x206               [ PF IF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0
```

Because `rdx` and `r15` are both null, the conditions for the second one-gadget are solved!  Calculating the libc base address using the leaked `main_arena` address is trivial.  The following steps to wrap up this challenge are: 

* allocate a 0x70 size chunk and pass in a 0x23 padding followed by the address of `libc_base + 0xdf54f` to overwrite `__malloc_hook`
* allocate any size chunk to trigger `malloc`, `__malloc_hook` and the one-gadget
* get flag!

Unfortunately I did not have a chance to finish this exploit before the competition concluded, and instead proved the exploit on Ubuntu 20.04. The 20.04 libc.so.6 file has slightly different one-gadget addresses, however the conditions for the gagdets are the same as the challenge libc. 

