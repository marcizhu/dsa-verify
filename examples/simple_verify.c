#include <string.h>
#include <stdio.h>

#include "dsa_verify.h"

int main()
{
	const char* message = "The quick brown fox jumps over the lazy dog\n";

	const char* public_key =
		"-----BEGIN PUBLIC KEY-----\n"
		"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\n"
		"uTLUFAGFQNiCTKka0fGf7zeC5cgdqQqJhbsi\n"
		"-----END PUBLIC KEY-----\n";

	const char* signature =
		"MEQCIBsQNidBcx7MOGcMEkItVEx0iru9T7Ln6cN+3OMB5lie"
		"AiADvUlM2HhsZk9Uq/hK/DsSd6/+aMUMqeCDu92vPVuNBQ==";

	if(dsa_verify_blob(message, strlen(message), public_key, signature) == DSA_VERIFICATION_OK)
		puts("Verification OK");
	else
		puts("Verification FAILED");
}
