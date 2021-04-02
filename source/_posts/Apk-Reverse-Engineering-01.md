---
title: Apk Reverse Engineering 01
date: 2021-04-02 22:44:08
tags: Andoird
---
本文主要内容包含一些基本的反编译、重打包、签名、修改 app 行为的方法

# Background

OWASP MSTG project 设计了一系列 （故意包含 vulnerability 的） apk 练手项目，其中包含4个 level，每个 level 都是通过一个 challenge 的形式，教会学习者某些技能点。
本文，即 Level1，关注了 root 检测绕过，而 challenge 本身是寻找关键的 secret key。

<!--more-->

# Installation of Uncrackable Level 1 APK

首先安装[Level_01/UnCrackable-Level1.apk](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk)
{% asset_img uncrackable1.png %}
下载完成后，使用 adb 安装到 genymotion 的安卓模拟器里，或者直接拖拽apk安装包进去也可，打开会看到以下画面
<div style="width:50%;margin:auto">{% asset_img initalStart.png %}</div>
点击 ok 后程序会自动退出,这代表了程序中包含某些逻辑判断，使得程序不能在 root 下运行。
由于 genymotion 的 Android API 是默认 root 状态，因此我们需要绕过这段逻辑。
解决这第一个问题的办法有很多，例如动态 hook 从而在运行时解除限制、动态 debug 调试，这里我们采用第三种办法：逆向。通过反编译程序，找到判断推出的逻辑，进而删除这段逻辑达到绕过的目的。

# Root detection Bypass
## Decompilation

为了理解反编译，我们可以先从编译过程开始学起。同时为了方便理解，这里将这个过程和 Java 的进行比较。
编译一份 Java 代码时需要进行以下步骤：
* 写一份 Main.java 源代码
* 通过 javac 将 Main.java 编译为 Main.class，即字节码
* JVM(Java Virtual Machine) 进行解析，使用 JIT(Just-in-time) 将 Main.class 转化为 machine code 机器码
* machine code 被 CPU 执行，程序最终运行

{% asset_img decompile1.png %}
相比较而言，Android 的编译过程与以上 Java 的编译过程最大的区别在于，Android 并不使用 JVM 。原因是安卓仅有有限的处理器和内存，不适合支持 JVM。
所以，Android 引入了 Dalvik Virtual Machine (DVM)，过程如下：

{% asset_img decompile2.png %}
Android的字节码叫做 Dalvik bytecode（为了与 Java 原生 bytecode 进行区分），以 \*.dex 形式存储。它是 Android 源代码经过编译后产生的，之后会和 resources、manifest、META-INF 等一起打包成 zip 包，也就是我们熟悉的 \*.apk 安装包。
首先解压APK压缩包：
{% codeblock lang:bash %}
apktool d -f -r Uncrackable-Level1.apk 
{% endcodeblock %}

## Smali files
这里 -r 选项会自动将 \*.dex 文件转化为 smali 文件。
Smali 在安卓里的角色很类似与汇编代码在 Windows 里的角色。相比与 Dalvik bytecode 来说，smali 会更加肉眼可读一些。
执行完毕后得到 Uncrackable-Level1 文件夹，内容如下：
{% codeblock lang:bash %}
.
├── AndroidManifest.xml
├── apktool.yml
├── build
│   └── apk
├── original
│   ├── AndroidManifest.xml
│   └── META-INF
├── res
│   ├── layout
│   ├── menu
│   ├── mipmap-hdpi-v4
│   ├── mipmap-mdpi-v4
│   ├── mipmap-xhdpi-v4
│   ├── mipmap-xxhdpi-v4
│   └── mipmap-xxxhdpi-v4
├── resources.arsc
└── smali
    └── sg
        └── vantagepoint
            ├── a
            │   ├── a.smali
            │   ├── b.smali
            │   └── c.smali
            └── uncrackable1
                ├── a.smali
                ├── MainActivity$1.smali
                ├── MainActivity$2.smali
                └── MainActivity.smali
{% endcodeblock %}

## Modification

正常来说，如果我们要查看一个 apk 包里的可读 java 代码，需要首先使用 apktool，再使用 dex2jar，最后 jd-gui，步骤很多过于复杂。
其实有个更简便的小工具叫 Bytecode Viewer，可以直接将 apk 转化为可读 java 源代码，减少我们的人工工作。
不管怎么说，条条大路通罗马。最后的打开界面如下：
{% asset_img decompileView.png %}
可以直接查看（反编译得到的 smali 文件）被解析成 java 源代码的形式，其中有一段代码很有意思:
{% codeblock lang:java %}
private void a(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() {
        /* class sg.vantagepoint.uncrackable1.MainActivity.AnonymousClass1 */

        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}

/* access modifiers changed from: protected */
public void onCreate(Bundle bundle) {
    if (c.a() || c.b() || c.c()) {
        a("Root detected!");
    }
    if (b.a(getApplicationContext())) {
        a("App is debuggable!");
    }
    super.onCreate(bundle);
    setContentView(2130903040);
}

{% endcodeblock %}
以上的逻辑就是在 onCreate 创建活动的时候，首先进行 c.a() || c.b() || c.c() 的三种方式判断是否为 root 环境，
如果是的话，则执行 a() 函数，同时将 "Root detected!" 作为报错信息传入。
a() 函数除了弹出一个报错框提示之外，还有我们关心的退出逻辑，即点击 ok 按钮后触发 onClick 函数，调用 System.exit(0) 退出程序。
因此这里最简单的方法去绕过 root 检测就是直接将这个 exit(0) 命令删除。为了做到这个，我们需要直接去修改 smali 文件。
{% asset_img commentOutExit.png %}
将这一行注释掉，然后重新打包一个新的 apk
{% codeblock lang:bash %}
apktool b UnCrackable-Level1 -o new_uncrackable.apk
{% endcodeblock %}
{% asset_img newUncrackable.png %}
这样我们就重打包出了一个新的 apk，然后尝试把它安装回 genymotion 的模拟器
{% asset_img problem.png %}
这里一定会遇到一个问题：INSTALL\_PARSE\_FAILED\_NO\_CERTIFICATES
让我们在下一节看看为什么会出现这个问题。

## Signing APK and rebuilding

Android 使用了一个证书机制（certificate 和 keystore）来验证 apk 的任何未来的更新都来自于原作者，从而防止恶意攻击者篡改伪造。
一个数字证书通常包括一对公私钥，还有一些其他辅助信息，例如 key 的主人姓名、地点等，当给一个 apk 进行签名时，签名工具会把这个数字证书附上去，从而就与原作者的 private key 一一绑定。Keystore 是一个 binary 文件，存储一个或多个 private key。
接下来我们就要创建一个自己的 keystore
{% asset_img keystore.png %}
然后给我们刚刚重打包的 apk 签名
{% asset_img sign.png %}
最后我们可以尝试重新将新的 apk 包安装回模拟器了，这次应该没问题了。
{% asset_img reinstall.png %}
这一次虽然还是会弹出检测到不是 root 环境，但是不会强制退出。我们可以专注于解谜游戏了。
{% asset_img noForceExit.png %}

# Solving challenge

解谜游戏本身是要求输入一个 secret string，从而进行比对。经过一番研读程序（ verify 函数）我们可以看出，下图的 a.a(bArr, bArr2) 会输出 secret string 的值。
{% asset_img funcA.png %}
这里我们使用（强大的）frida 工具，编写 Javascript 脚本去动态 hook 这个函数，修改函数实现，将 secret string 打印在控制台上。
* 首先，在宿主机上下载安装[frida](https://github.com/frida/frida)
* 在安卓模拟器上启动 frida server

{% asset_img downloadFrida.png %}

{% codeblock lang:bash %}
adb root #可能需要
adb push ./frida-server-14.2.10-android-x86 /data/local/tmp
adb shell "chmod 755 /data/local/tmp/frida-server-14.2.10-android-x86"
adb shell "/data/local/tmp/frida-server-14.2.10-android-x86 &"
{% endcodeblock%}

* 编写 Javascript 脚本 hook 进程

{% codeblock lang:javascript %}
// exp1.js
Java.perform(function () {
    var aes = Java.use("sg.vantagepoint.a.a");

    //hook the function inside the class
    aes.a.implementation = function(var0, var1) {

        //calling the function itself to get its return value
        var decrypt = this.a(var0, var1);
        var flag = "";

        //converting the returned byte array to ascii and appending to a string
        for(var i = 0; i < decrypt.length; i++) {
            flag += String.fromCharCode(decrypt[i]);
        }

        //leaking our secret
        console.log(flag);
        return decrypt;
    }
});
{% endcodeblock %}

* 使用 frida 找到 uncrackable 进程，运行脚本

{% asset_img hook.png %}
这时检查模拟器上程序运行状态，在输入框里随意输入一些字符，触发 verify 函数
{% asset_img verify.png %}
可以发现在控制台上打印出了正确的 secret string: I want to believe
重新输入验证结果正确
<div style="width:50%;margin:auto">{% asset_img success.png %}</div>
至此，Challenge 1 解谜结束。
