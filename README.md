# SHA-K library

Secure Hash Algorithm library implementation in C
According to [FIPS 180-4 Standard](https://doi.org/10.6028/NIST.FIPS.180-4)

---

The **sha256.c** file now computes sha256 hash successfully <br>
(*The test vectors are from [here](https://www.di-mgt.com.au/sha_testvectors.html)*)

<br>

```bash
PS C:\Users\elfurioux\Desktop\shak-lib> bin/sha.exe "abc"
sha256: 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```
ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

<br>

```bash
PS C:\Users\elfurioux\Desktop\shak-lib> bin/sha.exe ""
sha256: 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855

<br>

```bash
PS C:\Users\elfurioux\Desktop\shak-lib> bin/sha.exe "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
sha256: 0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
```
248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1

<br>

```bash
PS C:\Users\elfurioux\Desktop\shak-lib> bin/sha.exe "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
sha256: 0xcf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1
```
cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1

---

Originally the name was **shaC** standing obviously for **SHA** in **C**
But i wanted the pronouciation to be SHA-K, so this is its name.
