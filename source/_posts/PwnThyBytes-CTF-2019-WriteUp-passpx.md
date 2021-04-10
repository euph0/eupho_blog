---
title: PwnThyBytes CTF 2019 WriteUp - passpx
date: 2021-04-10 17:14:35
tags: CTF
---

# 0x00

关闭地址随机化
{% codeblock lang:bash %}
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space
{% endcodeblock %}

试运行
{% asset_img 2.png %}

<!--more-->
# 0x01 尝试脱壳

用IDA打开后，发现用的是upx壳，只是不是标准的upx壳，所以无法使用upx -d直接脱壳。
因为输入缺少参数时，会报错"Usage: passpx password"，而这一步会进行系统调用 syscall write，所以在这里断点，因为按道理来说这里已经程序解完壳了
{% codeblock lang:bash %}
gdb -ex 'start' -ex 'catch syscall write' -ex 'c' --args ./passpx aaa
{% endcodeblock %}

然后使用vmmap dump内存
{% asset_img 3.1.png %}

这里看到别的wp上面写的是从 0x400000 到 0x414000 就可以了，但是我自己尝试了之后发现只 dump 这一段后面放进 IDA 会报错打不开，所以这里我是从 0x400000 到 0x613000 的。

{% asset_img 3.2.png %}

把 dump 出来的东西放到 IDA 里看一下，从 start 进去，会发现首先将函数 sub\_4001A0 压入寄存器保存起来，点进去看应该是关键函数

{% asset_img 5.png %}

# 0x02 分析关键函数

分析sub\_4001A0，程序一开始有一处明显的比较判断
{% asset_img 6.1.png %}
因此尝试将这串作为输入的参数，果然失败
{% asset_img 6.2.png %}
继续往下分析，结论是这串代码主要是针对 byte\_614060 处的字符串或者 byte\_61507F 处的字符串进行 RC4 解密。具体怎么看出来是 RC4 的，注释见图。
{% asset_img 6.3.png %}
{% asset_img 6.4.png %}
{% asset_img 6.5.png %}

在gdb里面把这两处字符串的值打印出来
{%asset_img 6.6.png %}
然后使用接下来的脚本手动将RC4解密
{% codeblock lang:python %}
from Crypto.Cipher import ARC4
import binascii
import struct

rc4 = ARC4.new(struct.pack('<Q', 0x12345678AABBCCDD)) # little-endian, unsigned long long
plaintext = rc4.decrypt(binascii.unhexlify('C5E8D9409A5C748153B6D3EBDA5245'))
print(plaintext)


rc4 = ARC4.new(struct.pack('<Q', 0x12345678AABBCCDD)) # little-endian, unsigned long long
plaintext = rc4.decrypt(binascii.unhexlify('C5E8D9409A5C748153B6B699DB63D93565FF7D3718A74D8B3AE5C4F9CB6486F4CE21C96803BA0D488B15630C140D523A83B4FDC82B43CD1F3A21'))
print(plaintext)
{% endcodeblock %}

得到的结果刚好是输出的报错信息
{% asset_img 6.7.png %}
其实当时没看明白这里是在干什么，等题目做完了返回头分析，这里应该就是个幌子，并没有什么真的判断，相反只是在针对输出信息进行 RC4 解密。所以真正的参数判断还在别的地方。

# 0x03 换思路，动态调试

上面的步骤走进了一条死胡同，只能换思路分析。这一次不直接dump了，而是选择从初始程序直接跟进去。为了调试方便，我选择了利用IDA远程调试。方法参见[IDA远程调试](https://blog.csdn.net/lacoucou/article/details/71079552)

首先在start处下一个断点，遇到call F7进去
{% asset_img 7.1.png %}
{% asset_img 7.2.png %}
{% asset_img 7.3.png %}
{% asset_img 7.4.png %}

直到遇到一个关键的跳转 jmp r13，此时r13的值为0x7FFFF7FF8F60（所以这里一定要关地址随机化，不然后面地址一直在变会把自己搞死）

ps. 这里为了方便自己可以在 409F44 下个断点
{% codeblock lang:bash %}
gdb -ex 'start' -ex 'b *0x409f44' -ex 'c' --args ./passpx aaa
{% endcodeblock %}

进去0x7FFFF7FF8F60了之后调试几次就会发现，这里有一个非常非常长的循环，在IDA里面看会看到很多固定的16进制数，特征非常像md5。

如果一直跟这个循环可能100年都要过去了，所以快一点就是在这里要跳转到8F8C的时候把鼠标光标移到下面的8FAD，然后按F4：execute instructions until instruction under the cursor is reached

{% asset_img 7.5.png %}
{% asset_img 7.6.png %}
{% asset_img 7.7.png %}
{% asset_img 7.8.png %}

调用链是8F60 → 8FA5 → 8F8c → ...(反复的循环) → 8FAB → 8FAD → 8FAE → A3B2 → A3CE → A286
最后进来的这个A286函数是最终要的hash_check函数，

最开始会有一个判断 cmp esi, 112h(这一句找到的过程很是曲折，但后来发现其实在那句jmp r13之后跳转到0x7ffff7ff段之后一直F7就能到)，第一次进入这里的时候esi的值为0x82，调试的时候是选择在这里下一个断点，然后继续F9/continue。最后esi的值会依次经过0x82, 0x82, 0x99db，最后变成0x112(但是不明白这里在干什么)。

{% asset_img 7.9.png %}

通过了之后会对每一个字节进行比较，所以这里的逻辑就是刚刚前面的大循环是在做md5（input），哈希出来的结果在这里与应编码的结果进行比较，看是否等于E6442DF67CEB507E9E75C2A2FC4EA3CD.
这里没法直接破解md5，因此解决办法是当cmp esi， 0x112通过的时候，强行修改eip为A309，原因是这一句刚好是上面所有的判断结束后的第一句，这样我们就绕过了hash_check。

{% asset_img 7.10.png %}
{% asset_img 7.11.png %}
{% asset_img 7.12.png %}

这一步结束之后，直接F9，程序正常执行完毕退出。
{% asset_img 7.13.png %}

此时返回linux查看，flag已经输出。
{% asset_img 7.14.png %}

0x04 后记

其实上一步修改完eip之后可以选择继续跟，

{% asset_img 8.1.png %}

就会发现程序神奇的进入了我们一开始在IDA里看到的那个RC4函数，只不过那个时候byte_61507F里面的值更新了，不再是try harderer，

{% asset_img 8.2.png %}

再重新解密出来就是flag。

{% codeblock lang:python %}
rc4 = ARC4.new(struct.pack('<Q', 0x12345678AABBCCDD)) # little-endian, unsigned long long
plaintext = rc4.decrypt(binascii.unhexlify('c1cee223a67b7ddd52f0d0adeb57e20450c91b5c759b70e201dea8d0e847f4d6e203bb412fc47266f3334a1e501a1763a6'))
print(plaintext)
{% endcodeblock %}

{% asset_img 8.3.png %}
