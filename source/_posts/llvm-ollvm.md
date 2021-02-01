---
title: LLVM & OLLVM & (?)LLVM
categories: 代码保护
date: 2021-02-01 11:45:08
mathjax: true
---

## 经典编译器设计
一个传统静态编译器（像大多数C编译器）最流行的设计是3阶段的设计，其中主要组件是前端，优化器及后端（如下图）
<!-- more -->
![Typical Design of Modern Compiler](arch.png)
前端：负责解析源代码，检查错误，并构建一个特定于语言的抽象语法树（AST）来代表输入的代码
* (optional) AST被转换到一个新的用于优化的表示，优化器及后端可以运行这个代码

优化器：负责进行各种转换尝试改进代码的运行时间，比如重复计算消除，通常或多或少与语言及目标无关
后端：也被称为代码产生器；把代码映射入目标指令集，通用部分包括指令选择，寄存器分配，及指令调度
$\clubsuit$ 为什么要这样设计？
当一个编译器决定支持多个源语言或目标架构时，这种经典设计最重要的收益出现了
如果编译器在其优化器中使用一个通用的代码表示，那么可以为任何可以编译到这个表示的语言编写一个前端，且为任何可以从这个表示编译得到的目标编写一个后端，如下图所示
![Retargetablity](retarget.png)
否则，实现一个新源语言将要求从头开始，因此支持N个目标及M个源语言将需要N*M种编译器

## LLVM

### LLVM的代码表示：LLVM IR (Frontend)

### LLVM是一个库的集合 (Optimizer)

### LLVM代码生成器的设计 (Backend)

## 编写一个自己的LLVM Pass

### 安装

### 添加新pass

### 重新编译

### 测试

## OLLVM

### 指令替换 (Instruction Substitution)

### 控制流平坦化 (Control Flow Flattening)

### 控制流伪造 (Bogus Control Flow)

### 字符串混淆 (String Obfuscation)

### 注解 (Annotation)

## (?)LLVM

### 一些代码/二进制混淆技术

### 可以参考的测试集

