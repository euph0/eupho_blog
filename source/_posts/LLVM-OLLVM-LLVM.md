---
title: LLVM & OLLVM & (?)LLVM
date: 2021-04-04 18:55:32
tags: LLVM
---
# 经典编译器设计

{% asset_img compilerConcept.png %}
一个传统静态编译器（像大多数C编译器）最流行的设计是3阶段的设计，其中主要组件是前端，优化器及后端（如上图）

<!--more-->

前端：负责解析源代码，检查错误，并构建一个特定于语言的抽象语法树（AST）来代表输入的代码
* （optional）AST被转换到一个新的用于优化的表示，优化器及后端可以运行这个代码

优化器：负责进行各种转换尝试改进代码的运行时间，比如重复计算消除，通常或多或少与语言及目标无关
后端：也被称为代码产生器；把代码映射入目标指令集，通用部分包括指令选择，寄存器分配，及指令调度

**为什么要这样设计?**
当一个编译器决定支持多个源语言或目标架构时，这种经典设计最重要的收益出现了
如果编译器在其优化器中使用一个通用的代码表示，那么可以为任何可以编译到这个表示的语言编写一个前端，且为任何可以从这个表示编译得到的目标编写一个后端，如下图所示
{% asset_img modernCompiler.png %}
否则，实现一个新源语言将要求从头开始，因此支持 N 个目标及 M 个源语言将需要 N\*M 种编译器

# LLVM

LLVM 过去是 Low Level Virtual Machine 的首字母缩写，但现在只是这个综合项目的一个标签，并因某些很好的工具而闻名（比如 Clang 编译器，一个在 GCC 编译器上提供了若干好处的 C/C++/Objective-C 编译器）

## LLVM的代码表示：LLVM IR（Frontend）
LLVM 现在被用作一个通用的基础设施来实现各种静态及运行时编译的语言，其设计最重要的方面是 LLVM 中间表示（IR）
* 在一个基于 LLVM 的编译器中，一个前端负责对输入代码解析，验证及诊断错误，然后把解析的代码转换到 LLVM IR（通常，但不总是，通过构建一棵 AST，然后把这个 AST 转换为 LLVM IR）。这个 IR 可选地通过一系列改进代码的分析及优化遍，然后发送到一个代码生成器来产生本地机器码

下面是一个简单的.ll文件例子：
{% codeblock %}
define i32 @add1(i32 %a, i32 %b) {
entry:
  %tmp1 = add i32 %a, %b
  ret i32 %tmp1
}

define i32 @add2(i32 %a, i32 %b) {
entry:
  %tmp1 = icmp eq i32 %a, 0
  br i1 %tmp1, label %done, label %recurse

recurse:
  %tmp2 = sub i32 %a, 1
  %tmp3 = add i32 %b, 1
  %tmp4 = call i32 @add2(i32 %tmp2, i32 %tmp3)
  ret i32 %tmp4

done:
  ret i32 %b
}
{% endcodeblock %}
这个 LLVM IR 对应以下 C 代码，它提供了两个不同的方式来加整数：
{% codeblock %}
unsigned add1(unsigned a, unsigned b) {
  return a+b;
}

// Perhaps not the most efficient way to add two numbers.
unsigned add2(unsigned a, unsigned b) {
  if (a == 0) return b;
  return add2(a-1, b+1);
}
{% endcodeblock %}

## LLVM是一个库的集合（Optimizer）

除了 LLVM IR 设计，LLVM 下一个最重要的方面是，它被设计为一组库，而不是作为一个整体命令行编译器，例如 GCC
优化器从读入 LLVM IR 代码开始，经过很多种不同的优化（optimization passes），根据输入的不同，对IR进行针对性的一些改变
* 在这里每个 pass 都被写成一个 C++ 类，由 Pass 类继承而来
* 大多数的 pass 都是写在一个单独的类文件(.cpp)中的，这些pass文件都被编译成为 .o 文件，接着会被链接打包成为一系列 .a 库文件，这些库文件提供了很多分析与翻译的功能
* Pass 之间都尽可能松地耦合：相互之间尽可能保持独立，或者明确定义 Pass 之间的依赖关系，方便 PassManager 管理与正确执行
这种基于库的实现方式允许 LLVM 提供大量的功能，如果你只是需要 LLVM 中的一些简单的功能，那么只需要指定运行的 pass 文件而不需要管所有的优化 pass

## LLVM代码生成器的设计（Backend）

LLVM 代码生成器负责把 LLVM IR 转换为目标特定的机器代码
和优化器采用的方式类似，LLVM 的代码生成器将代码生成的问题分离成独立的 pass，例如指令选择，寄存器分配，建表，代码布局优化以及提供默认的内建 pass 等等

# 编写一个自己的LLVM pass

网上有很多这样的教程参考，但仔细阅读之后发现都是基于相对很老的版本，内容方法与最新的版本出入很大，因此此处基于[latest官方文档](https://llvm.org/docs/WritingAnLLVMNewPMPass.html)编写一个自定义的 pass “HelloWorld”，能够打印出所有 non-external 函数名

## 安装

*Software Requirements*
CMake >=3.13.4 GCC >=5.1.0 python >=3.6 zlib >=1.2.3.4 GNU Make 3.79 3.79.1
*Installations*
{% codeblock lang:bash %}
# check out the LLVM project:
# Change directory to where you want the llvm directory placed.
git clone https://github.com/llvm/llvm-project.git

# build LLVM and Clang
cd llvm-project
mkdir build && cd build
cmake -DLLVM_ENABLE_PROJECTS=clang -G "Unix Makefiles" ../llvm
make
{% endcodeblock %}
执行以上命令之后，大概需要等五个小时，就可以编译成功
可以尝试通过执行以下命令检查安装是否成功
{% codeblock lang:bash %}
clang --help
make check-clang
{% endcodeblock %}
{% blockquote %}
Reference: [Getting Started: Building and Running Clang](https://clang.llvm.org/get_started.html)
{% endblockquote %}

## 添加新pass

* 在 llvm/include/llvm/Transforms/ 目录下新建文件夹 HelloWorld，然后新建文件 HelloYichen.h，里面内容如下：

{% codeblock lang:c %}
#ifndef LLVM_TRANSFORMS_HELLOWORLD_HELLOYICHEN_H
#define LLVM_TRANSFORMS_HELLOWORLD_HELLOYICHEN_H

#include "llvm/IR/PassManager.h"

namespace llvm {
    class HelloYichenPass : public PassInfoMixin<HelloYichenPass> {
        public:
            PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
    };
} // namespace llvm
#endif
{% endcodeblock %}

* 在 llvm/lib/Transforms/ 目录下新建文件夹 HelloWorld，然后新建文件 HelloYichen.cpp，里面内容如下：

{% codeblock lang:c %}
#include "llvm/Transforms/HelloWorld/HelloYichen.h"

using namespace llvm;

PreservedAnalyses HelloYichenPass::run(Function &F,
        FunctionAnalysisManager &AM) {
    errs() << "Hello " << F.getName() << "\n";
    return PreservedAnalyses::all();
}
{% endcodeblock %}

* 修改 llvm/lib/Transforms/CMakelists.txt，添加

{% codeblock %}
add_subdirectory(HelloWorld)
{% endcodeblock %}

* 修改 llvm/lib/Passes/PassRegistry.def，添加

{% codeblock %}
FUNCTION_PASS("helloyichen", HelloYichenPass())
{% endcodeblock %}

* 修改 llvm/lib/Passes/PassBuilder.cpp，添加

{% codeblock lang:c %}
#include "llvm/Transforms/HelloWorld/HelloYichen.h"
{% endcodeblock %}

* 修改 llvm/lib/Passes/CMakelists.txt，在DEPENDS里添加
{% codeblock %}
HelloWorld
{% endcodeblock %}

## 重新编译

{% codeblock lang:bash %}
cd build/
make
{% endcodeblock %}
大概需要等待半小时左右，打印以下信息即编译完毕
{% asset_img compilationSucceeds.png %}

## 测试

* 新建任意一个 .c 文件：

{% codeblock lang:c %}
#include <stdio.h>

int sum(int a, int b) {
    return a + b;
}

int main () {
    int a = 10, b = 10;
    a = sum(a, b);
    printf("%d\n", a);
}
{% endcodeblock %}

* 编译生成 LLVM 可视化字节码文件

{% codeblock lang:bash %}
clang -O3 -emit-llvm test.c -S -o test.ll
{% endcodeblock %}

* 测试编写的 pass

{% codeblock lang:bash %}
llvm-project/build/bin/opt -disable-output test.ll -passes=helloyichen
{% endcodeblock %}
输出以下内容即为正确
{% asset_img hello.png %}

# OLLVM

OLLVM（Obfuscator-LLVM）是瑞士西北应用科技大学安全实验室于2010年6月份发起的一个项目，该项目旨在提供一套开源的针对 LLVM 的代码混淆工具，以增加对逆向工程的难度
简单来说，OLLVM 最大的贡献就是在 LLVM 的基础上添加了以下提供代码混淆功能的 Pass

## 指令替换 (Instruction Substitution)

本质上指令替换就是用等价的更加复杂的指令替换原本可读性更好的指令。比如，加减以及布尔指令

## 控制流平坦化 (Control Flow Flattening)

该模式改变原本程序的控制流，主要是把一些 if-else 语句，嵌套成 do-while 语句
例如源程序的控制流和经过平坦化后的控制流如下：
* before:

{% asset_img before.png %}

* after:

{% asset_img after.png %}

## 控制流伪造 (Bogus Control Flow)

也是对程序的控制流做操作，不同的是，BCF 模式会在原代码块的前后随机插入新的代码块，新插入的代码块不是确定的，然后新代码块再通过条件判断跳转到原代码块中
并且原代码块可能会被克隆并插入随机的垃圾指令

## 字符串混淆  (String Obfuscation)

混淆后的字符串没办法直接搜索到，变成一系列操作后的合成产物，提高了反编译成本

## 注解 (Annotation)

有的时候，由于效率或其他原因的考虑，我们只想给指定的函数混淆或不混淆该函数，OLLVM也提供了对这一特性的支持，你只需要给对应的函数添加 attributes 即可
例如想对函数foo()使用fla混淆:
{% codeblock lang:c %}
int foo() __attribute((__annotate__(("fla"))));
int foo() {
   return 2;
}
{% endcodeblock %}

# (?)LLVM

上面提到的 OLLVM 是一个开源的、相对成熟的解决方案，但由于
* 该项目自从 llvm\_4.0 之后就不再提供官方开源维护
* 已经有了一些针对 OLLVM 的一些自动 deobfuscator 的插件

因此，为了代码保护能够保证一定强度和稳定性，同时参考业内商业产品的核心原理，建议基于OLLVM进行定制化的修改

## 一些代码/二进制混淆技术

### 条件异常

很多指令和系统操作都可以被用来产生异常，例如非法指令、整数运算、浮点数运算和内存访问操作等
条件异常只在设定的条件满足时才会触发异常处理，这样便可以实现程序控制权的转移，从而用来隐藏程序的真正执行流程，增大静态分析的复杂度和抵抗符号执行
{% asset_img conditionalException.png %}

### 不透明谓词

谓词 P 在程序中的某一点 p，如果在混淆之后对于混淆这是可知的（基于先验知识）而对于其他人是难以获知的，则称该谓词为不透明谓词
不透明谓词可以被用来向顺序执行的代码中插入条件恒为真或者横为假的路径分支，这些路径分支不影响代码的实际执行顺序，只是使代码的控制流变得复杂且难以分析
{% asset_img opaquePredicates.png %}
{% blockquote %}
Reference: {% asset_link sp-paper.pdf %}
{% endblockquote %}

### 切片克隆

这种方法将程序重要代码进行切片，针对每个代码片段克隆多个等价片段且生成多条随机执行路径，增加代码执行路径的随机多样性，是的攻击者难以恢复和分析原始代码
{% blockquote %}
Reference: {% asset_link ANewCodeObfuscationSchemeforSoftware.pdf %}
{% endblockquote %}

### 常量混淆

通过将常量转化为一系列的运算结果横相等的指令，可以隐藏原始的常量值
{% asset_img binaryPatch.png %}
{% blockquote %}
Reference: {% asset_link AnLLVMObfuscatorForBinaryPatchGeneration.pdf %}
{% endblockquote %}

### 插入dead code

往原始代码里插入一些dead code，它们要么永远不会被执行，要么即使会被执行，执行完毕的结果也不会被使用

### 别名转换 (Aliasing )

别名是指两个甚至更多的不同命名的变量其实指向同一块内存空间，在进行控制流分析时，Aliasing非常重要，例如
{% codeblock lang:c %}
i = 0;
*p = 1;
while (i < 5) {
	*p = *p + i;
	i = i + 1;
}
foo(i);
{% endcodeblock %}
如果这里\*p是i 的一个别名，那么整个循环只会执行两次就跳出，且i的值为7；如果不是别名的话，整个循环要执行5次，且i的值最后会是5

### 更复杂的算术替换

{% codeblock %}
x + y = x - ¬ y - 1
      = (x ⊕ y) + 2·(x ∧ y)
      = (x ∨ y) + (x ∧ y)
      = 2·(x ∨ y) - (x ⊕ y)
{% endcodeblock %}

## 可以参考的测试集

[obfuscation-benchmarks](https://github.com/tum-i4/obfuscation-benchmarks)


