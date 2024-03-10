# SHA-K library

Secure Hash Algorithm library implementation in C
According to [FIPS 180-4 Standard](https://doi.org/10.6028/NIST.FIPS.180-4)

## Here's some test vectors to test the CLI
(*The test vectors are from [here](https://www.di-mgt.com.au/sha_testvectors.html)*)

```powershell
PS D:\dev\shak-lib> $h = "abc"
PS D:\dev\shak-lib> bin/shak $h --hash sha1 -v=1; bin/shak $h --hash sha224 -v=1; bin/shak $h --hash sha256 -v=1; bin/shak $h --hash sha384 -v=1; bin/shak $h --hash sha512 -v=1
sha1: 0xa9993e364706816aba3e25717850c26c9cd0d89d
sha224: 0x23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
sha256: 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
sha384: 0xcb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
sha512: 0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
```

<b>Input message</b>: `abc`
<table>
    <thead align="center">
        <tr>
            <td>Algorithm</td>
            <td>Output</td>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th>SHA-1</th>
            <td>a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d</td>
        </tr>
        <tr>
          <th>SHA-224</th>
          <td>23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7</td>
        </tr>
        <tr>
          <th>SHA-256</th>
          <td>ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad</td>
        </tr>
        <tr>
          <th>SHA-384</th>
          <td>cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed [<i>truncated</i>]</td>
        </tr>
        <tr>
          <th>SHA-512</th>
          <td>ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a [<i>truncated</i>]</td>
        </tr>
    </tbody>
</table>

<hr>

```powershell
PS D:\dev\shak-lib> $h = " " # The program converts it to a null string
PS D:\dev\shak-lib> bin/shak $h --hash sha1 -v=1; bin/shak $h --hash sha224 -v=1; bin/shak $h --hash sha256 -v=1; bin/shak $h --hash sha384 -v=1; bin/shak $h --hash sha512 -v=1
sha1: 0xda39a3ee5e6b4b0d3255bfef95601890afd80709
sha224: 0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
sha256: 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
sha384: 0x38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
sha512: 0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
```

<b>Input message</b>: <i>`nothing`</i>
<table>
    <thead align="center">
        <tr>
            <td>Algorithm</td>
            <td>Output</td>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th>SHA-1</th>
            <td>da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709</td>
        </tr>
        <tr>
          <th>SHA-224</th>
          <td>d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f</td>
        </tr>
        <tr>
          <th>SHA-256</th>
          <td>e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855</td>
        </tr>
        <tr>
          <th>SHA-384</th>
          <td>38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da [<i>truncated</i>]</td>
        </tr>
        <tr>
          <th>SHA-512</th>
          <td>cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce [<i>truncated</i>]</td>
        </tr>
    </tbody>
</table>

<hr>

```powershell
PS D:\dev\shak-lib> $h = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
PS D:\dev\shak-lib> bin/shak $h --hash sha1 -v=1; bin/shak $h --hash sha224 -v=1; bin/shak $h --hash sha256 -v=1; bin/shak $h --hash sha384 -v=1; bin/shak $h --hash sha512 -v=1
sha1: 0x84983e441c3bd26ebaae4aa1f95129e5e54670f1
sha224: 0x75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525
sha256: 0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
sha384: 0x3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b
sha512: 0x204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445
```

<b>Input message</b>: `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq`
<table>
    <thead align="center">
        <tr>
            <td>Algorithm</td>
            <td>Output</td>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th>SHA-1</th>
            <td>84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1</td>
        </tr>
        <tr>
          <th>SHA-224</th>
          <td>75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525</td>
        </tr>
        <tr>
          <th>SHA-256</th>
          <td>248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1</td>
        </tr>
        <tr>
          <th>SHA-384</th>
          <td>3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 [<i>truncated</i>]</td>
        </tr>
        <tr>
          <th>SHA-512</th>
          <td>204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 [<i>truncated</i>]</td>
        </tr>
    </tbody>
</table>

<hr>

```powershell
PS D:\dev\shak-lib> $h = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
PS D:\dev\shak-lib> bin/shak $h --hash sha1 -v=1; bin/shak $h --hash sha224 -v=1; bin/shak $h --hash sha256 -v=1; bin/shak $h --hash sha384 -v=1; bin/shak $h --hash sha512 -v=1
sha1: 0xa49b2446a02c645bf419f995b67091253a04a259
sha224: 0xc97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3
sha256: 0xcf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1
sha384: 0x09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039
sha512: 0x8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909
```

<b>Input message</b>: `abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu`
<table>
    <thead align="center">
        <tr>
            <td>Algorithm</td>
            <td>Output</td>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th>SHA-1</th>
            <td>a49b2446 a02c645b f419f995 b6709125 3a04a259</td>
        </tr>
        <tr>
          <th>SHA-224</th>
          <td>c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3</td>
        </tr>
        <tr>
          <th>SHA-256</th>
          <td>cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1</td>
        </tr>
        <tr>
          <th>SHA-384</th>
          <td>09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 [<i>truncated</i>]</td>
        </tr>
        <tr>
          <th>SHA-512</th>
          <td>8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 [<i>truncated</i>]</td>
        </tr>
    </tbody>
</table>
