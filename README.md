# 示例代码
```cpp
#include<stdio.h>
#include "ShellcodeCryptor.h"
#pragma comment(lib,"ShellcodeCryptor.lib")
// 示例shellcode
unsigned char shellcode[536] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0x53,
    0x56, 0x57, 0x8B, 0x40, 0x30, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x00, 0x8B,
};

int main() {
    // Base64编码
    char* base64Encode_shellcode = Base64EncodeBytes(shellcode, sizeof(shellcode));

    // Base64解码
    int shellcodeSize = 0;
    unsigned char* base64decode_shellcode = Base64DecodeToBytes(base64Encode_shellcode, &shellcodeSize);

    // AES加密
    int encryptSize = 0;
    unsigned char* aesEncrypt_shellcode = AESEncrypt(shellcode, sizeof(shellcode), &encryptSize, "1234567891234567", "1234567891234567");

    // AES解密
    int decryptSize = 0;
    unsigned char* aesDecrypt_shellcode = AESDecrypt(aesEncrypt_shellcode, encryptSize, &decryptSize, "1234567891234567", "1234567891234567");

    return 0;
}
```

