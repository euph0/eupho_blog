---
title: Apk Reverse Engineering 02
date: 2021-04-03 00:26:46
tags: Android
---
本文主要内容包含一些基本的jdb使用方法

# Background

还是针对 Level 1 的 apk 项目进行练手，只是这次使用的方法不再是通过 reverse engineering， 而是动态 jdb 调试

<!--more-->

# Attach the debugger

{% codeblock lang:bash %}
# run the app in "wait for debugger" mode:
adb shell am start -D -n "owasp.mstg.uncrackable1/sg.vantagepoint.uncrackable1.MainActivity"

# find PID by running:
adb shell ps | grep uncrackable

# transfer debugging information from the device (emulator) to the local machine(debugger) via a established socker connection
adb forward tcp:RANDOM_PORT jdwp:PID

# verify that there is a socket listening
lsof -i -P -n | grep LISTEN

# suspend the execution of the app upon debugger connecting to it
(echo suspend && cat) | jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=RANDOM_PORT
{% endcodeblock %}

# Bypass root detection

使用set方法 set <value> = <expr> 可以修改变量/数组元素/...的值
{% asset_img setValue.png %}
这样弹窗提示就会变成可以取消模式，在弹窗外面点击一下鼠标，程序就可以继续而不会强制退出了

# Solving Challenge

为了找到secret的值，需要首先去找到这个值存储在哪里
{% asset_img decompile.png %}
通过阅读分析源代码（可以将某些变量名进行 refactor → rename），可以发现 secret 会成为 java.lang.String.equals 的参数被调用，与输入进行比对
这里直觉上我们应该直接在 java.lang.String.equals 处下一个断点，但很快我们会发现这个调用了太多次，会很容易迷失
更好的办法是，我们在更上一层的 javax.crypto.Cipher.doFinal 处下断电，等程序在这里断下来之后，再在 java.lang.String.equals 上下断点，如下图：
{% asset_img setBreakpoint.png %}
这里没有什么指示说 “I want to believe” 一定是 secret，因此能断下来之后这里的值都需要尝试一下。

