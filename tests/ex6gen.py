from os import path

# Example from https://www.di-mgt.com.au/sha_testvectors.html
#
# Algorithm     Output
# SHA-1         7789f0c9 ef7bfc40 d9331114 3dfbe69e 2017f592
# SHA-224       b5989713 ca4fe47a 009f8621 980b34e6 d63ed306 3b2a0a2c 867d8a85
# SHA-256       50e72a0e 26442fe2 552dc393 8ac58658 228c0cbf b1d2ca87 2ae43526 6fcd055e
# SHA-384       5441235cc0235341 ed806a64fb354742 b5e5c02a3c5cb71b 5f63fb793458d8fd ae599c8cd8884943 c04f11b31b89f023
# SHA-512       b47c933421ea2db1 49ad6e10fce6c7f9 3d0752380180ffd7 f4629a712134831d 77be6091b819ed35 2c2967a2e2d4fa50 50723c9630691f1a 05a7281dbe6c1086
# SHA-3-224     c6d66e77ae289566 afb2ce39277752d6 da2a3c46010f1e0a 0970ff60
# SHA-3-256     ecbbc42cbf296603 acb2c6bc0410ef43 78bafb24b710357f 12df607758b33e2b
# SHA-3-384     a04296f4fcaae148 71bb5ad33e28dcf6 9238b04204d9941b 8782e816d014bcb7 540e4af54f30d578 f1a1ca2930847a12
# SHA-3-512     235ffd53504ef836 a1342b488f483b39 6eabbfe642cf78ee 0d31feec788b23d0 d18d5c339550dd59 58a500d4b95363da 1b5fa18affc1bab2 292dc63b7d85097c

# Input message: the extremely-long message "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
#  repeated 16,777,216 times: a bit string of length 233 bits (~1 GB). This test is from the SHA-3 Candidate
#  Algorithm Submissions document. The results for SHA-3 are from the Keccak Known Answer Tests.

FILENAME = "example6.txt"

# check if the file already exist or is the name of an existing directory (might avoid path mistakes idk)
if path.isfile(FILENAME) or path.isdir(FILENAME):
    raise FileExistsError("File exists already, choose another name.")

with open(file=FILENAME,mode="wb") as fstream:
    for _ in range(16_777_216):
        fstream.write(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")
print("done!")
