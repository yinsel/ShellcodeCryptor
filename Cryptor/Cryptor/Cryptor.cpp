#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include "ShellcodeCryptor.h"
#pragma comment(lib,"ShellcodeCryptor.lib")

void printUsage() {
	printf("Usage:\n");
	printf("\tAES:\n");
	printf("\t\tCrypto.exe -e AES <file> <key> <iv>\n");
	printf("\t\tCrypto.exe -d AES <file> <key> <iv>\n");
	printf("\tRC4:\n");
	printf("\t\tCrypto.exe -e RC4 <file> <key>\n");
	printf("\t\tCrypto.exe -d RC4 <file> <key>\n");
}

int main(int argc, char* argv[])
{
	if (argc != 4 && argc != 5 && argc != 6) {
		printUsage();
		return -1;
	}
	if ((strcmp(argv[1], "-e") != 0 && strcmp(argv[1], "-d") != 0) || (strcmp(argv[2], "RC4") != 0 && strcmp(argv[2], "AES") != 0)) {
		printUsage();
		return -1;
	}
	struct stat fileInfo;
	FILE* file;
	if (stat(argv[3], &fileInfo) != 0) {
		printf("\nFile not exist\n");
		return -1;
	}
	unsigned char* buffer = new unsigned char[fileInfo.st_size];
	char* outFileName = new char[strlen(argv[3]) + 9];
	file = fopen(argv[3], "rb");
	fread(buffer, 1, fileInfo.st_size, file);
	fclose(file);
	if (strcmp(argv[1], "-e") == 0) {
		if (strcmp(argv[2], "RC4") == 0) {
			RC4(buffer, fileInfo.st_size, argv[4]);
			sprintf(outFileName, "%s_encrypt", argv[3]);
			file = fopen(outFileName, "wb");
			fwrite(buffer, 1, fileInfo.st_size, file);
			fclose(file);
			printf("\nOutFile: %s\n", outFileName);
		}
		if (strcmp(argv[2], "AES") == 0) {
			if (argc != 6) {
				printUsage();
				return -1;
			}
			int reusltSize = 0;
			unsigned char* result = AESEncrypt(buffer, fileInfo.st_size, &reusltSize,argv[4], argv[5]);
			sprintf(outFileName, "%s_encrypt", argv[3]);
			file = fopen(outFileName, "wb");
			fwrite(result, 1, reusltSize, file);
			fclose(file);
			printf("\nOutFile: %s\n", outFileName);
		}
	}
	if (strcmp(argv[1], "-d") == 0) {
		if (strcmp(argv[2], "RC4") == 0) {
			RC4(buffer, fileInfo.st_size, argv[4]);
			sprintf(outFileName, "%s_decrypt", argv[3]);
			file = fopen(outFileName, "wb");
			fwrite(buffer, 1, fileInfo.st_size, file);
			fclose(file);
			printf("\nOutFile: %s\n", outFileName);
		}
		if (strcmp(argv[2], "AES") == 0) {
			if (argc != 6) {
				printUsage();
				return -1;
			}
			int reusltSize = 0;
			unsigned char* result = AESDecrypt(buffer, fileInfo.st_size, &reusltSize, argv[4], argv[5]);
			sprintf(outFileName, "%s_decrypt", argv[3]);
			file = fopen(outFileName, "wb");
			fwrite(result, 1, reusltSize, file);
			fclose(file);
			printf("\nOutFile: %s\n", outFileName);
		}
	}
	return 0;
}
