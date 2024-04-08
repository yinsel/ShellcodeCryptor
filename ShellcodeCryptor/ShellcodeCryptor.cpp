#include "cryptopp.h"

void RC4(unsigned char* shellcode, int shellcodeSize, const char* key) {
    Weak::ARC4::Encryption enc;
    enc.SetKey((byte*)key, strlen(key));
    enc.ProcessData(shellcode, shellcode, shellcodeSize);
}

unsigned char* AESEncrypt(unsigned char* shellcode, int shellcodeSize, int* encryptDataSize, const char* key, const char* iv) {
    std::string data;
    unsigned char* result;
    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV((byte*)key, strlen(key), (byte*)iv,strlen(iv));

    StringSource s(shellcode, shellcodeSize, true,
        new StreamTransformationFilter(e,
            new StringSink(data)
        )
    );
    *encryptDataSize = data.size();
    result = new unsigned char[*encryptDataSize];
    memmove(result, data.data(), *encryptDataSize);
    return result;
}

unsigned char* AESDecrypt(unsigned char* shellcode, int shellcodeSize, int* decryptDataSize, const char* key, const char* iv) {
    std::string data;
    unsigned char* result;
    CBC_Mode< AES >::Decryption e;
    e.SetKeyWithIV((byte*)key, strlen(key), (byte*)iv,strlen(iv));

    StringSource s(shellcode, shellcodeSize, true,
        new StreamTransformationFilter(e,
            new StringSink(data)
        )
    );
    *decryptDataSize = data.size();
    result = new unsigned char[*decryptDataSize];
    memmove(result, data.data(), *decryptDataSize);
    return result;
}

char* Base64EncodeString(const char* str) {
    string encoded;

    Base64Encoder encoder(nullptr, false);
    encoder.Put((byte*)str, strlen(str));
    encoder.MessageEnd();

    size_t size = encoder.MaxRetrievable();
    if (size)
    {
        encoded.resize(size);
        encoder.Get((byte*)&encoded[0], encoded.length());
    }
    char* result = new char[encoded.length() + 1];
    result[encoded.length()] = '\0';
    strcpy(result, encoded.c_str());
    return result;
}

char* Base64EncodeBytes(unsigned char* bytes, int bytesDataSize) {
    string encoded;

    Base64Encoder encoder(nullptr, false);
    encoder.Put(bytes, bytesDataSize);
    encoder.MessageEnd();

    size_t size = encoder.MaxRetrievable();
    if (size)
    {
        encoded.resize(size);
        encoder.Get((byte*)&encoded[0], encoded.size());
    }
    char* result = new char[encoded.length() + 1];
    result[encoded.length()] = '\0';
    strcpy(result, encoded.c_str());
    return result;
}

unsigned char* Base64DecodeToBytes(const char* base64String, int* decodeDataSize) {
    string decoded;

    Base64Decoder decoder;
    decoder.Put((byte*)base64String, strlen(base64String));
    decoder.MessageEnd();

    size_t size = decoder.MaxRetrievable();
    if (size)
    {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }
    *decodeDataSize = decoded.size();
    unsigned char* result = new unsigned char[decoded.size()];
    memmove(result, decoded.data(), decoded.size());
    return result;
}

char* Base64DecodeToString(const char* base64String) {
    string decoded;

    Base64Decoder decoder;
    decoder.Put((byte*)base64String, strlen(base64String));
    decoder.MessageEnd();

    size_t size = decoder.MaxRetrievable();
    if (size)
    {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }
    char* result = new char[decoded.size() + 1];
    result[decoded.size()] = '\0';
    memmove(result, decoded.data(), decoded.size());
    return result;
}