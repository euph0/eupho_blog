---
title: Apk Reverse Engineering 03
date: 2021-04-04 16:55:17
tags: Android
---
# Background

本文旨在解决 OWASP Project Android 联手项目 Level 2，关注了root检测绕过和反调试检测，而challenge本身也是寻找关键的 secret string

<!--more-->

# Dive in

首先还是老样子，安装apk到安卓模拟器里
{% asset_img install.png %}
{% asset_img frida_fail.png%}

这时我们尝试去attach其中的一个进程会发现失败，失败原因后面会解释
那只能先反编译看一下源码了

{% codeblock lang:bash%}
# decompile and convert to source code
apkx -d cfr Uncrackable2-Level2.apk
{% endcodeblock %}

{% asset_img decompile.png %}

可以看到里面的一些特别之处在于：
* 静态load 了一个 libfoo.so
* 在 onCreate 方法里调用了 native 函数 init，另外这个 init 函数里面还又调用了 bar 函数

那么很显而易见，在这个库里肯定有文章
这里可以使用radare2/IDA查看

## Radare2

* 下载安装

{% codeblock lang:bash%}
# install radare2
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
{% endcodeblock %}

* 使用

{% codeblock lang:bash %}
# using radare2
> r2 ./libfoo.so
Cannot determine entrypoint, using 0x00000840.
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
 -- Here be dragons.
[0x00000840]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000840]> iE
[Exports]

nth paddr      vaddr      bind   type   size lib name
―――――――――――――――――――――――――――――――――――――――――――――――――――――
3   0x00001110 0x00001110 GLOBAL FUNC   175      Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
5   0x00001100 0x00001100 GLOBAL FUNC   15       Java_sg_vantagepoint_uncrackable2_MainActivity_init
14  ---------- 0x00004008 GLOBAL NOTYPE 0        _edata
15  ---------- 0x00004008 GLOBAL NOTYPE 0        __bss_start
16  ---------- 0x0000400d GLOBAL NOTYPE 0        _end

[0x00000840]> 
{% endcodeblock %}

在 radare2 里查看 Java_sg_vantagepoint_uncrackable2_MainActivity_init 函数
{% asset_img radare2.png %}

## IDA

或者，打开 IDA → Uncrackable-Level2/lib/libfoo.so 分析 init & bar 函数（好处是可以直接F5不用看汇编）
{% asset_img IDA.png %}
{% blockquote %}
We can see that the main process forks a child process that attaches to it as a debugger using ptrace. This is a basic anti-debugging technique.
{% endblockquote %}
这也就解释了为什么一开始我们使用 frida 注入的时候会失败，因为frida本身就是使用 ptrace 进行注入，因为本身父进程已经有 debugger attach 上去了

# Anti Anti-debugging

## Solution 1 - frida

关闭 Uncrackable2 程序，
{% codeblock lang:bash %}
frida -U -f owasp.mstg.uncrackable2 --no-pause
{% endcodeblock %}
**加上 -f 选项** 后，这里frida不再是注入到原有运行的 Uncrackable2 程序中，而是 “spawn the process”，即首先注入到 Zygote 里去，再启动 Uncrackable2 程序
{% asset_img frida-f.png %}

## Solution 2 - patching

另一种方式是 patch，即通过反编译、重打包、签名的流程来修改 apk，类似的操作我们在 Level 01 里也做过
{% codeblock lang:bash %}
apktool d -f -r UnCrackable-Level2.apk
vim UnCrackable-Level2/smali/sg/vantagepoint/uncrackable2/MainActivity.smali # 注释 init 调用，如下图
apktool b UnCrackable-Level2 -o new_uncrackable.apk # 重打包
zipalign -v 4 new_uncrackable.apk UnCrackable2.recompiled.aligned.apk # 对齐
keytool -genkeypair -v -keystore my_key.keystore -alias my_key -keyalg RSA -keysize 2048 -validity 10000 # 产生自己的keystore
jarsigner -verbose -keystore my_key.keystore UnCrackable2.recompiled.aligned.apk my_key # 签名
{% endcodeblock %}
{% asset_img comment.png %}
卸载原本的apk，安装新 patch 的apk
{% codeblock lang:bash %}
adb uninstall owasp.mstg.uncrackable2
adb install UnCrackable2.recompiled.aligned.apk
{% endcodeblock %}
重新运行程序，使用 frida 查看发现只剩一个进程了，即成功绕过反调试
{% asset_img reinstall.png %}
这一种方法在后面做题的时候其实会遇到问题
原因是：如果我们仔细观察 init 和 bar 函数，就会发现 init 函数中除了进行一次函数调用，还将 byte_400C 设置为 1
{% asset_img 400C.png %}
主要是这个值在后面 bar 函数起着关键作用，如果 byte_400C 值不为1，后面就不会进行 strncmp 调用
{% asset_img 400C1.png %}
所以这里我们直接在 smali 代码里注释掉 init 函数后，还需要额外补充 byte_400C = 1 这一步
{% codeblock lang:javascript %}
//Get base address of library
var libfoo = Module.findBaseAddress("libfoo.so");

//Calculate address of variable: its offset from the base address is 0x400C bytes, based on our disassembly
var initialized = libfoo.add(ptr("0x400C"));

//Write 1 to the variable
Memory.writeInt(initialized, 1);
{% endcodeblock %}

# Solving Challenge

## Bypass root detection

编写 frida 脚本，hook 掉 exit 方法
{% codeblock lang:javascript %}
setImmediate(function() {
    console.log("[*] Starting script");
    Java.perform(function() {
        var exitClass = Java.use("java.lang.System");
        exitClass.exit.implementation = function() {
            console.log("[*] System.exit called");
        }
        console.log("[*] Hooking calls to System.exit");
    });
});
{% endcodeblock %}
然后使用上一节的方法绕过 root 检测
{% asset_img bypassRoot.png %}
这时已经可以在输入框中尝试输入 secret string 了

## Solution 1 - reverse engineering

该输入什么呢？从前面的反编译分析可以看到，我们输入的input最后会作为参数被放进 libfoo.so 中的 bar 函数内，该函数最后返回一个 boolean 决定了我们的输入是否验证成功
{% asset_img bar.png %}
结合 bar 函数内容，显而易见首先校验我们输入的内容长度是否为 23，然后在于 v6 字符串（Thanks for all the fish）进行比对，如果一致则返回真
{% asset_img strncmp.png %}
因此输入内容即为以上字符串即可过关
{% asset_img success.png %}

## Solution 2 - frida

我们还可以通过使用 frida hook 关键的 strncmp 函数，然后打印出它的参数，这样就也可以知道 secret string 的值了
考虑到 strncmp 函数原型：
{% codeblock lang:c %}
int strncmp ( const char * str1, const char * str2, size_t num );
{% endcodeblock %}
编写脚本
{% codeblock lang:javascript %}
java.Perform(function) {
	
	//...

	var strncmp = undefined;

	imports = Module.enumerateImportsSync("libfoo.so");

	for(i = 0; i < imports.length; i++) {
    	if(imports[i].name == "strncmp") {
        	strncmp = imports[i].address;
        	break;
    	}
	}

	Interceptor.attach(strncmp, {
    	onEnter: function (args) {
        	if(args[2].toInt32() == 23 && Memory.readUtf8String(args[0],23) == "01234567890123456789012") {
            	console.log("[*] Secret string at " + args[1] + ": " + Memory.readUtf8String(args[1],23));
        	}
    	}
	});
});
{% endcodeblock %}

这个脚本在写的时候有几个注意点：
* 调用 Module.enumerateImportsSync 是为了获取 libfoo.so 中所有 import 组成的一个 array，具体API可以参考[手册](https://frida.re/docs/javascript-api/)
* Java 里的 String 是不以 null 结尾的。如果我们使用 Memory.readUtf8String 方法去获取 strncmp 参数中的字符串指针的内容，同时不指定长度时，frida 不能知道什么时候字符串结束。因此我们需要指定长度，23
* 如果我们不加以限制，直接打印出所有调用 strncmp 时的参数，会发现输出会爆炸多，因为这个函数在太多地方被调用。因此，这里的小 trick 是限制仅当与输入为“01234567890123456789012”（为什么是这个？23位啊）时才会输出

理论上这个方法应该是没什么问题的，但不知道为什么卡在了下面这个错误
{% asset_img error.png %}
目前来看有可能不是语法的错误，怀疑跟这个 [issue](https://github.com/frida/frida/issues/1398) 有关，因为这里用的安卓模拟器是genymotion，仅支持 x86 的CPU; 然后 frida 在支持 x86 上有个 bug，hook 短函数会失败 → 尚未验证

