---
title: XCTF 梅津美治郎 WriteUp
date: 2021-04-10 17:44:45
tags: CTF
---

第一个字符串直接很容易 直接硬编码
{% asset_img 1.png %}

第二个字符串这里我绕了很久，最后是要绕过反调试，进入0x401547

* od-选项-调试设置-勾上忽略int3 中断
* 在0x40161f下断点，然后F7 step into
* 进入调试进程的veh，0x40157F

<!--more-->

(原因是在00401B31处，程序调用了rtladdvectoredexceptionhandle(veh异常处理)，并将0x40157f作为参数传入)

{% asset_img 2.png %}

[神秘的call $+5 pop eax](https://blog.csdn.net/magictong/article/details/7610482)

{% asset_img 3.png %}

{% codeblock lang:python %}
a = [0x75, 0x31, 0x6e, 0x6e, 0x66, 0x32, 0x6c, 0x67]
res = []
for i in a:
    res.append(i ^ 0x2)
print(''.join([chr(item) for item in res]))
{% endcodeblock %}
