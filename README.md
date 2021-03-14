# DSA signature verification library :closed_lock_with_key:

Small & straightforward C library to verify a blob or hash of data against a DSA public key and a DSA signature. Cross-platform and with a small memory footprint. Very intuitive and fast. Easily usable with other languages such as C++ due to its simple interface.


## Generating DSA keys
In order to sign a document, you first need to create a DSA public/private key pair. This is easily doable using OpenSSL:
```sh
$ openssl dsaparam 4096 > dsaparam.pem
$ openssl gendsa -out dsa_priv.pem dsaparam.pem
$ openssl dsa -in dsa_priv.pem -pubout -out dsa_pub.pem
$ rm dsaparam.pem
```

After executing those commands, there should be two new files: `dsa_priv.pem` and `dsa_pub.pem`. This first one is your private key, and it will be used to sign documents. **DO NOT SHARE THAT FILE WITH ANYONE**, and backup it just in case. The other file is your public key, and it can be shared freely.


## Signing a file
To sign a document, one can use OpenSSL once again:
```sh
openssl dgst -sha1 -binary < file | openssl dgst -sha1 -sign dsa_priv.pem | openssl enc -base64
```

This command will sign the file `file` with the private key `dsa_priv.pem`. As a result, it will generate a signature encoded in [base64](https://en.wikipedia.org/wiki/Base64). You can save that signature in a plain text file.


## Verifying a signature with dsa-verify
In order to verify a signature, you need the file, the public key and the signature itself. After that, it is as simple as calling `dsa_verify_blob()`:

```c
#include "dsa_verify.h"

const char* contents = "The quick brown fox jumps over the lazy dog\n";

const char* public_key = 
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIGRzCCBDkGByqGSM44BAEwggQsAoICAQC8Kgf0rpKifA8/lAeAVago8W9YVKQK\n"
    "OoNkPiXkn80wDNdMfvSnnJdmHyIuYnNVb/Hfc902GvH9l8J/ZZm2cW8F7ZIUlcR5\n"
    // ....
    "uTLUFAGFQNiCTKka0fGf7zeC5cgdqQqJhbsi\n"
    "-----END PUBLIC KEY-----\n";

const char* signature =
    "MEQCIBsQNidBcx7MOGcMEkItVEx0iru9T7Ln6cN+3OMB5lie"
    "AiADvUlM2HhsZk9Uq/hK/DsSd6/+aMUMqeCDu92vPVuNBQ==";

if(dsa_verify_blob(contents, strlen(contents), public_key, signature) == DSA_VERIFICATION_OK)
    puts("Verification OK");
else
    puts("Verification FAILURE");
```

Take a look at [simple-verify.c](examples/simple-verify.c) for a complete working example.

It is also possible to verify the SHA1 hash of the file, or verify a SHA1 hash using a public key & signature in DER form (instead of the default PEM form). For more information, take a look at the [header file](include/dsa-verify.h) of the library.


## Compiling
The included Makefile will compile the library into a static library as well as compile the examples. You can also use the provided `CMakeLists.txt` in order to compile this library into a static library or integrate this project with yours.


## Credits
This library makes use of `mp_math`, a small subset of [LibTomMath](https://github.com/libtom/libtommath), in order to perform the key verification. It also uses a modified version of the [clibs/SHA1](https://github.com/clibs/sha1) implementation by Steve Reid, released into the Public Domain.


## License
Copyright (c) 2021 Marc Izquierdo  
This library is licensed under the [MIT License](https://choosealicense.com/licenses/mit/). See
[LICENSE](https://github.com/marcizhu/dsa-verify/blob/master/LICENSE) for more details.
