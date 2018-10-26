# PEKS

This is the implementation of public-key searchable encryption using bilinear maps described in Public Key Encryption with Keyword Search. It is a simple, command-line application developed in C.

## Implementation Details

#### 依赖

* GMP Library: 

  ```$ sudo apt-get install libgmp3-dev```
* OpenSSL: 

  ```$ sudo apt-get install libssl-dev```
* [PBC Library](https://crypto.stanford.edu/pbc)

  ```
  $ ./configure --prefix=$HOME/.local
  $ make
  $ make install
  ```
  Makefile uses this path. In case of change in destination directory, update the Makefile accordingly.

#### 编译

   ```$ make```

#### 运行

   ```$ ./peks <word1> <word2>```

#### 实例

```
$ ./peks hello hello
Equal
$ ./peks 123 12
Not equal
$ ./peks Supercalifragilisticexpialidocious Supercalifragilisticexpialidocious
Equal
```

#### 函数解析
**kenGen(key,param,pairing)**
key有两个成员，priv和pub，先随机生成priv=alpha，再随机生成pub.g，计算g^al

**H1(W1)**
hash(w)->hashedw->h1_w1->pairing

**Trapdoor(Tw, pairing,priv,h1_w1)**
Tw=h1_w1 ^ priv

**PEKS(peks,pub,pairing,h1_w,bits)**
随机生成r
hR=h^r
初始化t为Gt中的元素
t=e(h1_w,hR)=e(h1(w),h^r)
gR = g^r
t->String char_t
H2(t)->peks.B





This work was a part of the master thesis from TU Dresden under the supervision of Dr. Josef Spillner and Martin Beck.

## [Public Key Encryption with Keyword Search](http://eprint.iacr.org/2003/195.pdf) 

by Dan Boneh, Giovanni Di Crescenzo, Rafail Ostrovsky and Giuseppe Persiano.

The authors describe a way of appending information to a message that has been encrypted with a standard  public key cipher, which allows a server that doesn’t have the private key necessary to  decrypt the entire message to still be able to search for a certain set of keywords. For a keyword, a PEKS value can be generated which will allow the server to perform a search using a trapdoor.

