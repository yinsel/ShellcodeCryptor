#pragma once
// RC4
void RC4(unsigned char* shellcode, int shellcodeSize, const char* key);

// AES CBCģʽ
unsigned char* AESEncrypt(unsigned char* shellcode, int shellcodeSize, int* encryptDataSize, const char* key, const char* iv);
unsigned char* AESDecrypt(unsigned char* shellcode, int shellcodeSize, int* encryptDataSize, const char* key, const char* iv);

// Base64���룬�����ڲ�ͬ����
char* Base64EncodeString(const char* str);
char* Base64EncodeBytes(unsigned char bytes, int bytesDataSize);
unsigned char* Base64DecodeToBytes(const char* base64String, int* decodeDataSize);
char* Base64DecodeToString(const char* base64String);