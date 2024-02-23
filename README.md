# shak-lib

Secure Hash Algorithm library implementation in C
According to [FIPS 180-4 Standard](https://doi.org/10.6028/NIST.FIPS.180-4)

---

Originally the name was shaC standing obviously for **SHA** in **C**
But i wanted the pronouciation to be SHA-K, so this is its name.

---

The **sha256.c** file now computes sha256 hash successfully:
(The tests are from [here](https://www.di-mgt.com.au/sha_testvectors.html))

> PS C:\Users\elfurioux\Desktop\csha> ./sha.exe "abc"
> l=24=(0*512+24) k=423
l+1+k = 448 = 448mod512
block_count=1
=========================================================================================
6162638000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000018
=========================================================================================
ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

> PS C:\Users\elfurioux\Desktop\csha> ./sha.exe ""   
> l=0=(0*512+0) k=447
l+1+k = 448 = 448mod512
block_count=1
=========================================================================================
8000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
=========================================================================================
e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855

> PS C:\Users\elfurioux\Desktop\csha> ./sha.exe "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
> l=448=(0*512+448) k=511
l+1+k = 960 = 448mod512
block_count=2
=========================================================================================
6162636462636465 6364656664656667 6566676866676869 6768696A68696A6B 696A6B6C6A6B6C6D 6B6C6D6E6C6D6E6F 6D6E6F706E6F7071 8000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 00000000000001C0
=========================================================================================
248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1

> PS C:\Users\elfurioux\Desktop\csha> ./sha.exe "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
> l=896=(1*512+384) k=63
l+1+k = 960 = 448mod512
block_count=2
=========================================================================================
6162636465666768 6263646566676869 636465666768696A 6465666768696A6B 65666768696A6B6C 666768696A6B6C6D 6768696A6B6C6D6E 68696A6B6C6D6E6F
696A6B6C6D6E6F70 6A6B6C6D6E6F7071 6B6C6D6E6F707172 6C6D6E6F70717273 6D6E6F7071727374 6E6F707172737475 8000000000000000 0000000000000380
=========================================================================================
cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1
