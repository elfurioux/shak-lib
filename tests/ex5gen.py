from os import path

# Example from https://www.di-mgt.com.au/sha_testvectors.html
#
# Algorithm     Output
# SHA-1         34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f
# SHA-224       20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67
# SHA-256       cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0
# SHA-384       9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985
# SHA-512       e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b
# SHA-3-224     d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c
# SHA-3-256     5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1
# SHA-3-384     eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340
# SHA-3-512     3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87

# Input message: one million (1,000,000) repetitions of the character "a" (0x61).

FILENAME = "example5.txt"

# check if the file already exist or is the name of an existing directory (might avoid path mistakes idk)
if path.isfile(FILENAME) or path.isdir(FILENAME):
    raise FileExistsError("File exists already, choose another name.")

with open(file=FILENAME,mode="wb") as fstream:
    for _ in range(1_000_000):
        fstream.write(b'a')
print("done!")
