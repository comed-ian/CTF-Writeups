# BSides Noida CTF 2021 Binary Exploitation Challenge Write-ups

The following write-up includes two challenges from BSide's Noida CTF 2021 competition. 

## Table of Contents
* Baby Stack - 472 pts
* Warmup - 494 pts

## Baby Stack
tbc.

## Warmup
### Finding the Bug
This challenge is another standard ELF x86-64bit executable exploitation which allows the user to store entries interactively. Unfortunately the binary is stripped of symbols, making reversing and debugging a bit more challenging.  Running the executable shows an interactive menu that allows multiple options, all which seem familiar in a CTF challege:

```bash
=1= add
=2= show
=3= edit
=4= del
=5= save
=6= exit
> 
```

Browsing through disassembly indicates that there are a total of 16 indices available for storage, from 0-15. The search for the program's bug started by examing the multiple calls to `malloc` and `free`, since the input strings are stored dynamically on the heap. The first function of interest is the `save` option, which seems a bit redundant since the strings are all stored into memory by the `add` function. Decompilation shows that the save function takes a input index and stores it in `curr_index` is not already set to a valid storage index.  The `curr_index` value (an arbitrary variable name based on my analysis) is initially set to -1, so this function can only be used once in the program. Odd, but not individually useful.

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

Browsing the `delete` function reveals the utility of `save`. Decompilation shows that the program interacts expected...for some cases. If provided a valid index and a pointer at that index exists, then it is freed.  However, there is another conditional statement that begs further investigation: `if (input_index == curr_index) uaf_flag = 1;`.  If this condition is met, the array index is freed and a flag is set to 1, but the array index is *not* cleared, leading to a use after free vulnerability.  The flag prevents this condition from occuring again which restricts the user to a single UAF with which to work. This is still powerful, and enough to solve the challenge.

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
The key to this UAF is that the other menu options are still available to the corresponding index even after its pointer has been freed. This means that the `show` function will still print any data available at the residual pointer location; this can be used to leak a heap address if the freed chunk resides in fastbins (so long as it is the second or later entry in the bin) or a `main_arena` address if the chunk is located in the unsorted bin.  A heap address leak is included in the solution file, though it was not used for the exploit. Rather, the `main_arena` address was prioritized because none of the storage indices contain function pointers that can be corrupted to hijack execution flow.  Instead, leaking a `main_arena` address can set up a `__free_hook` or  `__malloc_hook` corruption when either function is called.
