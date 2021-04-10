---
title: Crypto CTF 2020 WriteUp
date: 2021-04-10 15:46:55
tags: CTF
mathjax: true
---
# TRAILING BITS

## Challenge

{% blockquote %}
The text that includes the flag is transmitted while unfortunately both of its head and tail bits are lost :(
{% endblockquote %}
题目给出了一个txt文件，内容是一个二进制串

<!--more-->
## Solution

根据题目可知字符串的头和尾有一些字符丢失了，但不影响flag字符串的内容。

{% codeblock lang:python %}
from Crypto.Util.number import *

flag = open("output.txt", "r").read().strip()

i = 1
while i < len(flag):
    data = long_to_bytes(int(flag,2) << i)
    if b'CCTF' in data:
        print(data)
        exit()
    i += 1
{% endcodeblock %}

## Flag

CCTF{it5\_3n0u9h\_jU5T\_tO\_sH1ft\_M3}

# GAMBLER

## Challenge

{% blockquote %}
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+ Hi, there is a strong relation between philosophy and the gambling!  +
+ Gamble as an ancient philosopher and find the flag :)                +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| Options:
|    [C]ipher flag!
|    [E]ncryption function!
|    [T]ry the encryption
|    [Q]uit
{% endblockquote%}

{% codeblock %}
def encrypt(m, p, a, b):
    assert m < p and isPrime(p)
    return (m ** 3 + a * m + b) % p
{% endcodeblock %}

## Solution

想要恢复flag就需要知道加密使用的参数a, b, p，然后解密还需要求解多项式函数。
题目提供了针对给定明文给出密文的服务，因此可以通过这一点求解参数。

多项式函数: 
$$\begin{equation}
f(x)=x^3+ax+b \quad mod \quad p
\end{equation}$$

因此，
$$\begin{equation}
f(0) = 0^3+0+b = b \quad mod \quad p
\end{equation}$$

$$\begin{equation}
f(1) = 1^3+a+b = 1+a+b \quad mod \quad p
\end{equation}$$

以上可以恢复a, b的值。
为了继续得到p的值，可以选择一个相对小的值m，使得f(m)\>p，因此：
$$\begin{equation}
\begin{aligned}
f(m) &= m^3+am+b \quad mod \quad p \\
f(m)+kp  &= m^3+am+b \\
kp &= m^3+am+b-f(m)
\end{aligned}
\end{equation}$$

等式右边都是已知项，左边k为一个很小的整数，可以进行爆破。
得到了所有的参数值后，可以利用sage进行多项式根的求解。
{% codeblock %}
PR.<x> = PolynomialRing(GF(p))
f = x^3 + a * x + b - enc
rts = f.roots()
print(rts)

for root in rts:
    flag = root[0]
    print(long_to_bytes(flag))
{% endcodeblock %}

# THREE RAVENS

## Challenge

{% blockquote %}
There were three ravens sat on a tree, Downe a downe, hay downe, a downe, They were as black as they might be.
{% endblockquote %}

{% codeblock %}
from Crypto.Util.number import *
from flag import flag

def keygen(nbit):
    while True:
        p, q, r = [getPrime(nbit) for _ in range(3)]
        if isPrime(p + q + r):
            pubkey = (p * q * r, p + q + r)
            privkey = (p, q, r)
            return pubkey, privkey

def encrypt(msg, pubkey):
    enc = pow(bytes_to_long(msg.encode('utf-8')), 0x10001, pubkey[0] * pubkey[1])
    return enc

nbit = 512
pubkey, _ = keygen(nbit)
print('pubkey =', pubkey)

enc = encrypt(flag, pubkey)
print('enc =', enc)
{% endcodeblock %}

## Solution

这题的加密过程是RSA的一种变形，只是相当于
$$\begin{equation}
N=(p·q·r)·(p+q+r)
\end{equation}$$

令
$$\begin{equation}
s = p·q·r
\end{equation}$$

$$\begin{equation}
t = p+q+r
\end{equation}$$

可以轻易证明得到:
$$\begin{equation}
m^e \quad mod \quad N ≡ m^e \quad mod \quad t
\end{equation}$$

这样就又回到了简单的RSA解密方式，为了解密我们需要得到
$$\begin{equation}
d = e^{-1} \quad mod \quad φ(t)
\end{equation}$$

又由于题目已知t为素数
$$\begin{equation}
φ(t) = t-1
\end{equation}$$

得解。

{% codeblock lang:python %}
from Crypto.Util.number import *

t = 31678428119854378475039974072165136708037257624045332601158556362844808093636775192373992510841508137996049429030654845564354209680913299308777477807442821
c = 8218052282226011897229703907763521214054254785275511886476861328067117492183790700782505297513098158712472588720489709882417825444704582655690684754154241671286925464578318013917918101067812646322286246947457171618728341255012035871158497984838460855373774074443992317662217415756100649174050915168424995132578902663081333332801110559150194633626102240977726402690504746072115659275869737559251377608054255462124427296423897051386235407536790844019875359350402011464166599355173568372087784974017638074052120442860329810932290582796092736141970287892079554841717950791910180281001178448060567492540466675577782909214
e = 0x10001

d = inverse(e, t-1)
m = pow(c, d, t)
print(long_to_bytes(m))
{% endcodeblock %}

## Flag

CCTF{tH3\_thr3E\_r4V3n5\_ThRe3\_cR0w5}

# MODEL

## Challenge

{% codeblock lang:python%}
def genkey(nbit):
    while True:
        p, q = getPrime(nbit), getPrime(nbit)
        if gcd((p-1) // 2, (q-1) // 2) == 1:
            P, Q = (q-1) // 2, (p-1) // 2
            r = inverse(Q, P)
            e = 2 * r * Q  - 1
            return(p, q, e)

def encrypt(msg, pubkey):
    e, n = pubkey
    return pow(bytes_to_long(msg), e, n)
{% endcodeblock %}

## Solution

$$\begin{equation}
\begin{aligned}
e &= 2·r·Q-1 \\
&= 2·Q^{-1}·Q-1 \quad mod \quad P \\
&=2-1 \quad mod \quad P \\
&=1 \quad mod \quad P
\end{aligned}
\end{equation}$$

所以e可以表示为
$$\begin{equation}
e = 1 + \frac{k(q-1)}{2}
\end{equation}$$

带入m，利用费马小定理得：
$$\begin{equation}
\begin{aligned}
m^e &= m^{1+\frac{k(q-1)}{2}} \quad mod \quad q \\
&=m·m^{\frac{k(q-1)}{2}}  \quad mod \quad q \\
&=m·(m^{q-1})^\frac{k}{2} \quad mod \quad q \\
&=m·1^\frac{k}{2} \quad mod \quad q \\
&=m·1^\frac{1}{2} \quad mod \quad q \\
&=±m \quad mod \quad q
\end{aligned}
\end{equation}$$

因此
$$\begin{equation}
m^e±m = 0 \quad mod \quad q
\end{equation}$$

可以通过求其与 n=p·q 的最大公约数得到q。
{% codeblock lang:python %}
from Crypto.Util.number import *
import math

def derive_e(p,q):
	P, Q = (q-1) // 2, (p-1) // 2
	r = inverse(Q, P)
	e = 2 * r * Q  - 1
	return e

n = 17790613564907955318126717576181316624843451677921227941389832111093895513875496295594784102148835715126789396535470416868485674231839509486983792844881941097589192520877472968227711640216343330193184235164710328845507199362646489303138765492026284976828397217700058854699501312701069031398507487060508966602815218264215778115331187180105972920333780067280854048113094622799996118383376340217782122945586262887450863620856214375258659362300743471229410735400189992359220551961441580630740022857304514895745174813529758766758733506538696933950282130984955594881517339093338779101106466633380921338845195921235252323721
flag_enc = 8216344743331409189205831776342200252705923796193752552649425282859227400617284746437075756157249953578189229459392338128783031841882560801175367779263048253787547952450480816724222285583987363793884961526545550108790689158473753461378651141379053427506957702375732452598640804768960184186521954448243004125900395894265450073650101942224629389391631821735998886688813393717718376391743836798122485350719355567861201466641767009303179260141365766023680788250688524528992952859061172438083227729190577738108854783536925967748199734513738782142055609101950770816942854252284355975365351013803601963990179403849614198536

m = bytes_to_long(b'0')
c = 8131881080215090371487466406674376044247120209816118806949066423689730735519795472927218783473464525260814227606067990363574576048132004742403517775620572793232598693334765641758830271460405790617624271060522834683042735967050146871067065889288923913486919193720360254923458500009885281654478144592942337767754315130844294762755237864506689552987776560881357285727629827190391683150994461127468196118126587159811046890420456603820675085450111755868116701855834309297184745623927049652098555126342100576188575279791066071616897443075423425299542959405192350563251777193668273523389978129359003036691597884885020756981

q = math.gcd(c - m, n)
assert isPrime(q)
p = n // q
e = derive_e(p, q)
d = inverse(e, (p-1)*(q-1))
m = pow(flag_enc, d, n)
print(long_to_bytes(m))
{% endcodeblock %}

## Flag

CCTF{7He\_mA1n\_iD34\_0f\_pUb1iC\_key\_cryPto9raphy\_iZ\_tHa7\_It\_l3ts\_y0u\_puBli5h\_4N\_pUbL!c\_k3y\_wi7hOuT\_c0mprOmi5InG\_y0Ur\_5ecr3T\_keY}

# ONE LINE CRYPTO

## Challenge

{% blockquote %}
A profile, a look, a voice, can capture a heart ♥ in no time at all.”
{% endblockquote %}

{% codeblock %}

#!/usr/bin/python

from Crypto.Util.number import *
from secret import m, n, x, y, flag

p, q = x**(m+1) - (x+1)**m, y**(n+1) - (y+1)**n
assert isPrime(p) and isPrime(q) and p < q < p << 3 and len(bin(p*q)[2:]) == 2048
enc = bytes_to_long(flag)
print(pow(enc, 0x10001, p*q))
{% endcodeblock %}

## Solution

这一题和普通的RSA的区别在于, n=p·q不知道，并且得来的方式就是靠随机数运算。
由于限制了 p<q<p<<3, 说明数值都不大，建议直接爆破。

{% codeblock lang:python %}
from Crypto.Util.number import *
from gmpy2 import is_prime
from tqdm import tqdm

primes = []

for x in tqdm(range(500)):
    for m in range(500):
        prime = x**(m+1) - (x+1)**m
        if prime.bit_length() > 2048: break
        if is_prime(prime):
            primes.append(prime)

c = 14608474132952352328897080717325464308438322623319847428447933943202421270837793998477083014291941466731019653023483491235062655934244065705032549531016125948268383108879698723118735440224501070612559381488973867339949208410120554358243554988690125725017934324313420395669218392736333195595568629468510362825066512708008360268113724800748727389663826686526781051838485024304995256341660882888351454147057956887890382690983135114799585596506505555357140161761871724188274546128208872045878153092716215744912986603891814964771125466939491888724521626291403272010814738087901173244711311698792435222513388474103420001421

for i in range(len(primes)):
    for j in range(i, len(primes)):
        pq = primes[i] * primes[j]
        if len(bin(pq)[2:]) == 2048:
            try:
                d = inverse(0x10001, (primes[i]-1) * (primes[j]-1))
                m = long_to_bytes(pow(c, d, pq))
                if b'CCTF' in m:
                    print(m)
            except ValueError:
                pass
{% endcodeblock %}

{% blockquote%}
注：实验下来gmpy2.is_prime()比Crypto.Util.number.isPrime()快很多。
{% endblockquote%}

## Flag

CCTF{0N3\_1!nE\_CrYp7O\_iN\_202O}
