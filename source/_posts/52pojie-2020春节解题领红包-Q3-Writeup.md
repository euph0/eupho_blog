---
title: 52pojie 2020春节解题领红包 Q3 Writeup
date: 2021-04-04 17:48:52
tags: Android
---
# 题目链接
[Happy_New_Year_2020_Challenge](https://down.52pojie.cn/Challenge/Happy_New_Year_2020_Challenge.rar)

<!--more-->

# 解题过程

## Java 层

首先题目给出来是一个apk
{% asset_img q.jpg %}
拖到jadx里打开查看
{% asset_img jadx.png %}
发现 onCreate 函数是在 java 层实现的，而 onClick 和checkFlag都是在 native 层实现的 Native 层


## Native 层

因此找到 libcrack\_j2c.so，拖进 IDA 里查看，找到其中的两个关键函数
{% asset_img funclist.png %}

### 一些准备工作

File → Load file → Parse C header file，导入 {% asset_link jni.h %}
选中函数的第一个 int 型参数，右键"Convert to struct \*"，在打开的框里选择 JNIEnv，点击 ok
{% asset_img jniEnv.png %}
选中函数名，右键“Force call type”
会发现大部分函数会变得更加可读一些

### 分析 onClick 函数

{% asset_img onClick.png %}
大意是首先判断输入长度是否为30，如果不满足则跳转输出“flag长度必须为30位”
如果满足的话，会调用 checkFlag 进行判断，返回一个boolean值对应输出正确与错误信息
因此关键就在 checkFlag 函数

### 分析 checkFlag 函数

首先一进来是反调试
{% asset_img antiDebug.png %}
之后是对三块内存进行字符串赋值，分别为:
* string 1: thisiskey 
* string 2: 52pojie\_2020\_happy\_chinese\_new\_year
* string 3: 20200125

然后开辟一块新内存存放 35 位的 byte 数组
{% asset_img byte.png %}
接下来会遍历数组，如果 i!=0 && i%4==0，选取 string3 中下标为 (i>>2)-1 的字符填进 byte 数组，否则选取 string2 中下标为 i 的字符填进 byte 数组
{% asset_img index.png %}
然后对这个 byte 数组做 md5 hash
{% asset_img hash.png %}
然后将 hash 结果与 string1 循环异或 j % len(string1)
{% asset_img xor.png %}
异或结果转 hex，不足 0xF 时高位补 0，得到 32 位字符串
{% asset_img toHex.png %}
将结果截取[1:31]，与输入进行比较
{% asset_img compare.png %}
因此我们只需要按照这个逻辑算一遍，就能知道答案是什么

### 编写exp

{% codeblock lang:python %}
import hashlib

str1 = "thisiskey"
str2 = "52pojie_2020_happy_chinese_new_year"
str3 = "20200125"

res = []

for i in range(35):
    if i != 0 and i % 4 == 0:
        res.append(str3[(i>>2)-1])
    else:
        res.append(str2[i])

res = hashlib.md5("".join(res)).digest()

code = []
for i in range(len(res)):
    tmp = ord(result[i]) ^ ord(str1[i % 9])
    code.append("%02x" % tmp)

print("".join(code)[1:31])
{% endcodeblock %}

{% asset_img output.png %}

输入即可得到正确结果
{% asset_img success.jpg %}

附：{% asset_link libcrack_j2c.so.idb %}
