#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "dsa-verify.h"

// This is a simple tool that allows anyone to easily verify DSA signatures from
// the command line

char* read_file(const char* path, size_t* len)
{
	FILE* f = fopen(path, "rb");
	fseek(f, 0, SEEK_END);
	size_t fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char* contents = malloc(fsize + 1);
	fread(contents, 1, fsize, f);
	fclose(f);

	if (len != NULL)
		*len = fsize;

	contents[fsize] = '\0';
	return contents;
}

int main(int argc, char* argv[])
{
	if(argc != 4)
	{
		puts("DSA verification tool");
		puts("Usage: ./dsa-verify <file> <public key> <signature>");
		return -1;
	}

	size_t file_len;
	char* file_contents = read_file(argv[1], &file_len);
	char* public_key = read_file(argv[2], NULL);
	char* signature = read_file(argv[3], NULL);

	int ret = dsa_verify_blob((const unsigned char*)file_contents, file_len, public_key, signature);

	if (ret == DSA_VERIFICATION_OK)
		puts("Verification OK");
	else
	{
		puts("Verification FAILED");

		switch (ret)
		{
			case DSA_VERIFICATION_FAILED: break;
			case DSA_KEY_PARAM_ERROR: puts("Key is invalid!"); break;
			case DSA_SIGN_PARAM_ERROR: puts("Signature is invalid!"); break;
			case DSA_KEY_FORMAT_ERROR: puts("Key format is invalid!"); break;
			case DSA_SIGN_FORMAT_ERROR: puts("Signature format is invalid!"); break;
		}
	}

	free(file_contents);
	free(public_key);
	free(signature);

	return !(ret == DSA_VERIFICATION_OK);
}
