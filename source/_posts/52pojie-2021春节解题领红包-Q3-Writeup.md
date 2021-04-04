---
title: 52pojie 2021春节解题领红包 Q3 Writeup
date: 2021-04-04 18:28:29
tags: Android
---
# 题目链接
[Happy_New_Year_2021_Challenge](https://down.52pojie.cn/Challenge/Happy_New_Year_2021_Challenge.rar)

<!--more-->

# 解题过程

## 绕过高版本 sdk 限制

一开始尝试安装 apk 失败
{% asset_img installFailure.png %}
失败原因是我手头上的安卓机版本（6.0）太低，中间饶了很多弯路（本来想重新刷机，但这个手机太旧了系统空间容量太小，总是失败）
最后的解决办法是给修改 apk 重打包，修改 xml 配置文件里的最低版本要求
修改 apktool.xml 中的 sdkinfo，将最小要求从 26 改成 23
{% codeblock %}
 sdkInfo:
   minSdkVersion: '23'
   targetSdkVersion: '30'
{% endcodeblock %}
修改 AndroidManifest.xml ，改成 true
{% codeblock %}
android:extractNativeLibs="true"
{% endcodeblock %}
之后重新打包就可以正常安装了

## Java 层

打开来还是 flag 输入框和验证框，拖到 jadx 里查看 java 代码
{% asset_img decompile.png %}
和 2020 年的题目类似，还是先对输入的 flag 长度是否等于 30 进行判断，然后进入到 native 层 so 库中的 check 函数进行判断

## Native层

所以我们去IDA里打开来看一下
找到 Java\_cn\_pojie52\_cm01\_MainActivity\_check 函数后，会发现里面首先调用了 sub\_7FA30F8B90 函数
{% asset_img sub_8B90.png %}
接着将返回结果和静态存储的一串数据进行了类似的操作后，得到 v9 和 v19
{% blockquote %}
后来参考了别人的wp，发现这里是 base64
{% endblockquote %}
{% asset_img base64.png %}
并且判断两个是否一致，一致就正常退出程序
{% asset_img compare.png %}
很显然，这里就是判断 flag 输入是否正确的地方
转回到 8B90 这个函数来分析，发现是个 rc4 解密，areyousure?????? 就是密钥
{% asset_img rc4.png %}
这里可以参考 [ctf-wiki](https://ctf-wiki.org/reverse/identify-encode-encryption/introduction/#rc4) 中常见加密算法识别，具体怎么看出来的在IDA里面也进行了备注
那么接下来就尝试通过IDA动态调试，在比对值是否一致的地方下断点，验证猜测

## 启用 IDA 动态调试
首先将 IDA → dbgsrv → android\_server64 拷贝到手机中，运行

{% codeblock lang:bash %}
adb shell "./android_server64 &"
adb forward tcp:23946 tcp:23946
adb shell "pm list packages -3" # -3指第三方应用
am start -D -n cn.pojie52.cm01/.MainActivity
{% endcodeblock %}

{% asset_img adb.png %}
然后 IDA → Debugger → Process options
{% asset_img debugOption.png %}
选择 Remote Android Debugger
{% asset_img remoteDebugger.png %}
在刚进入 check 函数处下一个断点，在while比对处再下一个断点
IDA → Debugger → Attach to process，选择 cn.pojie52.cm01
{% asset_img startDebug.png %}
开始调试，按 F5 进入伪代码模式，输入 flag，F9 运行至断点处，F7/8 单步
{% asset_img whileCompare.png %}
查看 v9 和 v19 的值
* v9:
{% asset_img v9.png %}
* v19:
{% asset_img v19.png %}

将 v9 转化为字符串：4Gs3oXXX9tTvGcXAVKP6t3Dty9KxMhgIC1AEjh1+
{% asset_img v9_str.png %}
解密得到输入值
将 v19 转化为字符串：5Gh2/y6Poq2/WIeLJfmh6yesnK7ndnJeWREFjRx8
{% asset_img v19_str.png %}
解密得到 flag
