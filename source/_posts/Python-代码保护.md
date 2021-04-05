---
title: Python 代码保护
date: 2021-04-05 11:39:51
tags: Python
---
# Background

Python 作为一门解释性语言，其特性决定了保护难度会比编译型的 C、C++ 要来的复杂许多。
通常情况下，我们要运行一个 python 代码会怎么做？
{% codeblock lang:bash %}
python test.py
{% endcodeblock %}

<!--more-->

真正的可执行文件当然不是普通的 .py 文件，我们可以使用 compileall 模块显示地查看编译完成的可执行文件 .pyc（Linux  平台下对应 .pyc, Windows 平台对应 .pyd）
{% codeblock lang:bash %}
$ python -m compileall test.py
Compiling test.py ...
$ ls
test.py     test.pyc
$ xxd test.pyc
00000000: 03f3 0d0a 9a87 6a60 6300 0000 0000 0000  ......j`c.......
00000010: 0003 0000 0040 0000 0073 1b00 0000 6400  .....@...s....d.
00000020: 0084 0000 5a00 0065 0000 6401 0064 0200  ....Z..e..d..d..
00000030: 8302 0047 4864 0300 5328 0400 0000 6302  ...GHd..S(....c.
00000040: 0000 0002 0000 0002 0000 0043 0000 0073  ...........C...s
00000050: 0800 0000 7c00 007c 0100 1753 2801 0000  ....|..|...S(...
00000060: 004e 2800 0000 0028 0200 0000 7401 0000  .N(....(....t...
00000070: 0061 7401 0000 0062 2800 0000 0028 0000  .at....b(....(..
00000080: 0000 7307 0000 0074 6573 742e 7079 7403  ..s....test.pyt.
00000090: 0000 0061 6464 0100 0000 7302 0000 0000  ...add....s.....
000000a0: 0169 0300 0000 6905 0000 004e 2801 0000  .i....i....N(...
000000b0: 0052 0200 0000 2800 0000 0028 0000 0000  .R....(....(....
000000c0: 2800 0000 0073 0700 0000 7465 7374 2e70  (....s....test.p
000000d0: 7974 0800 0000 3c6d 6f64 756c 653e 0100  yt....<module>..
000000e0: 0000 7302 0000 0009 03                   ..s......
{% endcodeblock %}
一般情况下，.pyc 文件会在一个 python 代码被 import 的时候自动由 Python 解释器创建完成，里面就是编译出来的 bytecode，之后运行的时候 Python 解释器会自动检查 .py 文件的修改时间是否迟于 .pyc 可执行文件
如果 .py 文件没有被修改，那么解释器会选择执行 .pyc 文件；如果 .py 被修改了，那么解释器会使用最新的 .py 文件，但也会重新再声成一份 .pyc 文件，以备下次使用。
这样做的目的很显然，就是为了加快一点速度。

# .pyc 为什么不能保护代码？

## 一开始的尝试

那再回到 Python 代码保护上来，是不是我们只要保存源代码 .py, 只给出可执行文件 .pyc 就可以了呢？
答案是否定的，Python 已经有了 uncompyle6 模块，适用于 Python 2.7 & 3.x，可以从 .pyc 一键还原 python 代码
{% codeblock lang:bash %}
$ pip install uncompyle6
$ uncompyle6 test.pyc
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.16 (default, Jan 27 2020, 04:46:15)
# [GCC 4.2.1 Compatible Apple LLVM 10.0.1 (clang-1001.0.37.14)]
# Embedded file name: test.py
# Compiled at: 2021-04-05 11:44:26


def add(a, b):
    return a + b


print add(3, 5)
# okay decompiling test.pyc
$ cat test.py
def add(a, b):
    return a+b

print(add(3, 5))
{% endcodeblock %}
可以看到，对 python 源代码是可以高度还原的。uncompyle6 的工作原理详见[github: uncompyle6](https://github.com/rocky/python-uncompyle6/)，其中很重要的一点是，uncompyle6 是根据 .pyc 前4个字节（magic number）来判断 python 代码版本的。

## 做出一点改进

既然 uncompyle6 是根据 magic number 进行处理的，是不是我修改一下 magic number 让它无法识别就可以达到目的了呢？
显然也是不行的，原因有以下两点：
* Python 版本就那么多，其实一个个枚举很容易找到正确的 magic number
* .pyc 里面其实包含很多可读信息，例如 import 了什么库，还有字符串也是直接可以看出来的

# 还有哪些现成方案？

除此以外还调研了有些其他的现成方案，例如
* pyminifier

通过调用第三方库，变量、函数名称混淆，增加阅读代码难度，但是可以轻易编写脚本去混淆，使代码变得可读

* pyinstaller+加壳混淆

通过调用开源PyCrypto，使用 --key=key-string 对代码进行加密，但是生成的是 Windows
平台下的 exe 可执行文件

* pyarmor

调用第三方库，把字节码做一定程度上的加密，并最后调用so文件来解密，但是so文件未作加固，可以直接逆向分析

# 初版方案

综合以上调研之后，得到了第一版的方案，主要做了以下几点：
* 修改 opcode 映射关系，参考[Python 与 opcode](http://phantom0301.cc/2017/03/24/pythonopcode/)
* 由于 opcode.py 里还是有相应的内容，并且为了做到字符串内容的保护，hook 了 Python 源代码
通过修改 Python/fileutils.c 中的 FILE\* \_Py\_fopen\_hook(const char \*pathname, const char \*mode) 函数，将 pyc 文件的打开过程添加一层解密
* 使用 ollvm 混淆我们修改的函数，增大 diff 逆向的难度
* Python 源码编译完成后，修改 lib/python3.5/py\_compile.py，在生成 pyc 文件之前添加一层 AES 加密
* 修改完毕所有的 Python 代码之后，使用以下命令将所有的 .py 文件编译成为加密的 .pyc 文件

{% codeblock lang:bash %}
python -m compileall <target_python_code_directory>
{% endcodeblock%}

* 最后，为了保护源码中硬编码的加密秘钥，在解密的步骤中添加了运行时自修改模块（SMC）

以上多个步骤结合起来，能够得到一款定制的 Python 解释器，被加密的 pyc 可执行文件只能使用这款解释器运行，同时使用者仅会获得 pyc 文件，也很难恢复出对应源码

该方案的主要缺点在于：
* 严重依赖 Python 版本，甚至每一个小版本都需要做特定的修改
* 一旦 import 过多的第三方库，运行加解密时间就会过长，难以接受
* 加密秘钥硬编码，易还原出修改后的 opcode 映射

# 第二版方案

在初版方案的基础上，修改加解密算法为 RC4，使用时分为 runtime 和 xcrypt 两个解释器
前者只能用于运行加密后的 pyc （提供给用户），后者还可以编译加密 python 代码

该方案的主要缺点在于：
* 依旧严重依赖 Python 版本
* 通过区分解释器是 opcode 还原难度倍增，但没有从根本上解决加密秘钥硬编码的问题

# 第三版方案

转化思路，将原来保护 Python 的问题利用 Cython 转化为保护 c 语言编译得到的 so 库的问题，再使用 VMProtect 针对 so 进行加壳，相比较起来优点在于：
* 运行速度提升了
* 使用 vmp 虚拟化增大了逆向难度
* 一旦保护方案失效了，攻击者获取的也是编译得到的 so 库（即代码逻辑），而不像之前的方案会直接获得 Python 源码
