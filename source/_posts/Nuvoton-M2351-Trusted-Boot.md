---
title: Nuvoton M2351 Trusted Boot
date: 2021-04-05 15:35:44
tags: Trusted Computing
---

# TL; DR

结论是SecureBoot + Trustzone能做到：
* 确保boot流程是可信可控
* 能提供一个安全的签名验证机制
* 保证运行时安全

<!--more-->

# 名词解释
NuBL1: secure bootloader

NuBL2: trusted boot code, customer loader

NuBL32: secure code

NuBL33: non-secure code

XOM: Execute-Only Memory

APROM: Application Program ROM，用来存储 application 代码

LDROM: ISP(In-System-Programming) Loader ROM，用来存储 Bootloader 固件

OTP: One-Time-Programmable Memory

NuBL2 Marker: consecutive 16-byte data, indicate the NuBL2 execution address and NuBL2 firmware information address.
The Secure Bootloader (NuBL1) will search the valid NuBL2 Marker first, and then obtain the NuBL2 firmware information to start the Secure Boot verification to NuBL2.

Exception Level: [privilege-and-exception-levels](https://developer.arm.com/architectures/learn-the-architecture/exception-model/privilege-and-exception-levels)

# 应用场景

通过TrustZone技术来保证安全启动，安全升级，防回滚攻击，安全存储，安全设备管理，安全调试等基础安全能力，并通过TrustZone技术来保证用户密码，生物特征的安全性。
{% asset_img Nuvoton-Secure-ARM-Cortex-M23-Fingerprint-Reader.jpg %}
{% asset_img finger_arch.png %}

# boot流程

{% asset_img bootSequence.png %}

# 固件验证机制

## Secure Bootloader（NuBL1）验证NuBL2

{% asset_img NuBL1.png %}

### 验证需要的组件

{% asset_img NuBL1_component.png %}

### Identification

验证NuBL2 ECC 公钥的hash是否一致
{% asset_img identification.png %}

### Authentication

使用ECC公钥验证ECDSA签名是否正确
{% asset_img authentication.png %}

### Integrity

验证NuBL2 firmware hash
{% asset_img integrity.png %}

## NuBL2验证NuBL32/33

验证NuBL32/33的流程与验证NuBL2的流程大致相同，区别在于
* 在进行 identification 的时候，BL1 使用了存储在 OTP0~3 中的公钥hash，而 BL2 使用了 encrypted NuBL32/33 Public Key Storage，因此需要先进行 AES 解密

{% asset_img NuBL2_identification.png %}

* NuBL32 info 存储在 secure Flash 中，而 NuBL33 info 在 non-secure Flash 中

# 验证实现细节

## NuBL2 verification function

NuBL2 can call VerifyNuBL3x() API directly to perform NuBL32/NuBL33 identification, authentication and firmware integrity.
All the verification functions in VerifyNuBL3x.c could be configured as XOM code in the XOM region. Even if ICE debug mode is entered, the source code and procedure in XOM region cannot be traced.
{% codeblock lang:c %}
#define ENABLE_XOM0_REGION (1)
{% endcodeblock%}

## NuBL32/NuBL33 Public Key Storage

An AES-256 key and IV (Initialization Vector) are declared in the NuBL2 project for decrypting the Public Key Storage to obtain the NuBL32/NuBL33 ECC public key.

{% asset_img publicKey.png %}

# 实验结果

## 实验1：引导启动+Trustzone权限控制

* BL32 (secure)
{% asset_img 6.1a.png %}
* BL33 (non-secure)
{% asset_img 6.1b.png %}
* 实验现象
{% asset_img 6.1.png %}

{% codeblock %}

CPU @ 64000000 Hz (Non-secure flash base: 0x40000)

+------------------------------------------+

|    SecureBootDemo - NuBL2 Sample Code    |

+------------------------------------------+


Current CFG0: 0xffffffdf.


[Device is successfully booting from Secure Bootloader(NuBL1) and device PID is 0x00235100]


NuBL2 ECC public key hash are:

    0xffffffff

    0xffffffff

    0xffffffff

    0xffffffff

    0xffffffff

    0xffffffff

    0xffffffff

    0xffffffff


NuBL2 F/W info in 0x00018000.

Data are:

    0x19385b75    0x9f3e5af0    0x99d5d432    0xaa342806

    0x750f22c5    0x41785395    0x71638f4a    0xe22c156a

    0xf113c491    0xb4d75e91    0x79fd7374    0x3dba4776

    0x4322e883    0xf59a9077    0x0e530cb3    0xd79fd7aa

    0x00000001    0x00000008    0x00000000    0x00003b38

    0x0000000c    0x20180918    0x00000000    0x00000000

    0xb37db884    0xac5bd510    0xaecc1b5d    0xe91cd5ce

    0xf6aad5fd    0xc31dc48f    0x3e681c1c    0x219fda87

    0x15531b62    0xc6effdb4    0xbf2f86f7    0x31c8e809

    0xf029cd1a    0x42ae57d4    0x6468a63a    0x9b14aedf

    0x14fa56ac    0xd80a1f1b    0x870ade9f    0xf535a24e

    0x33d13cff    0xcdc7508c    0x0a8d12a8    0x02bec2ec



NuBL2 identify NuBL32 public key and verify NuBL32 F/W integrity PASS.


NuBL2 identify NuBL33 public key and verify NuBL33 F/W integrity PASS.


Jump to execute NuBL32...



CPU @ 64000000 Hz

+-------------------------------------------+

|    SecureBootDemo - NuBL32 Sample Code    |

+-------------------------------------------+


System is executing in NuBL32.


Secure code is running ...


Secure PA11 LED On call by secure

Execute non-secure code ...



CPU @ 64000000 Hz

+-------------------------------------------+

|    SecureBootDemo - NuBL33 Sample Code    |

+-------------------------------------------+


System is executing in NuBL33.


Nonsecure code is running ...


Secure PA11 LED Off call by non-secure

!!---------------------------------------------------------------!!

                       <<< HardFault >>>

  [0x10040e4c] 0x600a STR 0x1 [0x4000482c]

  Illegal access to Secure PA in Nonsecure code.

!!---------------------------------------------------------------!!

{% endcodeblock%}

## 实验2：往OTP内烧写公钥hash

* OTP
{% asset_img OTP.png %}
* 实验现象
{% asset_img 6.2.png %}

{% codeblock %}
CPU @ 64000000 Hz (Non-secure flash base: 0x40000)

+------------------------------------------+

|    SecureBootDemo - NuBL2 Sample Code    |

+------------------------------------------+


Current CFG0: 0xffffffdf.


[Device is successfully booting from Secure Bootloader(NuBL1) and device PID is 0x00235100]


NuBL2 ECC public key hash are:

    0xe4735e14

    0x2f226588

    0x1674d9a4

    0x70c6c071

    0x06fe45ed

    0x5ddb4cb2

    0xabd707d5

    0x6393ee35


NuBL2 F/W info in 0x00018000.

Data are:

    0x19385b75    0x9f3e5af0    0x99d5d432    0xaa342806

    0x750f22c5    0x41785395    0x71638f4a    0xe22c156a

    0xf113c491    0xb4d75e91    0x79fd7374    0x3dba4776

    0x4322e883    0xf59a9077    0x0e530cb3    0xd79fd7aa

    0x00000001    0x00000008    0x00000000    0x00003b38

    0x0000000c    0x20180918    0x00000000    0x00000000

    0xb37db884    0xac5bd510    0xaecc1b5d    0xe91cd5ce

    0xf6aad5fd    0xc31dc48f    0x3e681c1c    0x219fda87

    0x9637e985    0xe45efcd2    0x4b90f802    0x499df41d

    0x1cbddc75    0x935e8297    0x1088c0bd    0x3f2b4fb3

    0xd662d4a6    0x668124d2    0xbd75d4b3    0x7e5b580b

    0xbd87b172    0x33687484    0xeba4238b    0xb771d320



NuBL2 identify NuBL32 public key and verify NuBL32 F/W integrity PASS.


NuBL2 identify NuBL33 public key and verify NuBL33 F/W integrity PASS.


Jump to execute NuBL32...



CPU @ 64000000 Hz

+-------------------------------------------+

|    SecureBootDemo - NuBL32 Sample Code    |

+-------------------------------------------+


System is executing in NuBL32.


Secure code is running ...


Secure PA11 LED On call by secure

Execute non-secure code ...



CPU @ 64000000 Hz

+-------------------------------------------+

|    SecureBootDemo - NuBL33 Sample Code    |

+-------------------------------------------+


System is executing in NuBL33.


Nonsecure code is running ...
{% endcodeblock %}

## 实验3：尝试二次修改OTP

{%asset_img 6.3a.png %}
{%asset_img 6.3b.png %}
{%asset_img 6.3c.png %}

## 实验4：验证 BL1 secureboot 逻辑链：修改 BL2公钥，使其与 OTP 不匹配


{%asset_img 6.4a.png %}
{%asset_img 6.4b.png %}
{%asset_img 6.4c.png %}

## 实验5：验证BL2 secureboot逻辑链

修改BL32 FW
{% asset_img 6.5a.png %}
修改BL32 FWinfo Hash
{% asset_img 6.5b.png %}

{% codeblock %}
CPU @ 64000000 Hz (Non-secure flash base: 0x40000)

+------------------------------------------+

|    SecureBootDemo - NuBL2 Sample Code    |

+------------------------------------------+


Current CFG0: 0xffffffdf.


[Device is successfully booting from Secure Bootloader(NuBL1) and device PID is 0x00235100]


NuBL2 ECC public key hash are:

    0xe4735e14

    0x2f226588

    0x1674d9a4

    0x70c6c071

    0x06fe45ed

    0x5ddb4cb2

    0xabd707d5

    0x6393ee35


NuBL2 F/W info in 0x00018000.

Data are:

    0x19385b75    0x9f3e5af0    0x99d5d432    0xaa342806

    0x750f22c5    0x41785395    0x71638f4a    0xe22c156a

    0xf113c491    0xb4d75e91    0x79fd7374    0x3dba4776

    0x4322e883    0xf59a9077    0x0e530cb3    0xd79fd7aa

    0x00000001    0x00000008    0x00000000    0x00003b38

    0x0000000c    0x20180918    0x00000000    0x00000000

    0xb37db884    0xac5bd510    0xaecc1b5d    0xe91cd5ce

    0xf6aad5fd    0xc31dc48f    0x3e681c1c    0x219fda87

    0xcf347c60    0x57989753    0xd328a35e    0x4865021c

    0xaeb61ee0    0x678c0233    0xa28016f0    0x6314807b

    0xf0c7b338    0x171d427a    0xae91ab5d    0xdfd711b6

    0xe9981085    0x7091d2c0    0x22cd3e89    0xe9563327




NuBL2 verifies NuBL32 FAIL.
{% endcodeblock %}

# 可能的攻击面

{% asset_img sequence.png %}
NuBL1是安全的：因为写在Mask ROM里面，不可修改
BL1引导BL2的过程是怎么保证安全：BL1会去验证BL2的ECDSA签名，私钥是开发者管理
BL2是安全的：secure flash
BL2引导BL3的过程是怎么保证安全：同理，验证ECDSA签名

**问题是**：
* 引导跳过Secure Bootloader（BL1）

User Configuration block 是 4 个 32bit 的字（CONFIG0, CONFIG1, CONFIG2 and CONFIG3），其中 CONFIG0 的 5th bit 和 7th bit 负责控制 booting 的来源。
{% asset_img configBlock.png %}
{% asset_img erase.png %}
{% asset_img erase_pic.png %}

* dump：可以直接拿到BL32的secure code，内存未加密
