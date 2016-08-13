# X509Importer
X509Importer is a small library for importing DER-encoded public key files which follow the X.509 SubjectPublicKeyInfo format into .NET's Cryptography Next Generation library (or CNG for short). I originally wrote this library for my personal needs which is why it is by far not entirely standard compatible but at least I have been able to import both RSA and ECDSA keys I got from Java's PublicKey.getEncoded() method into .NET using it.

## Prerequisities:
In order to use this library you will need to target .NET version 3.5 or higher.

## Usage
Using this library is quite straightforward:

```C#
using BlackyPaw.Crypto;

// ...
// Import the DER file:
X509EncodedPublicKeyImporter importer = X509EncodedPublicKeyImporter.Import( <inputStreamHere> );

// for an RSA key:
CngKey rsaKey = ((RSAPublicKey) importer).ToCngKey();

// for an ECDH / ECDSA key:
CngKey ecdhKey = ((ECDSAPublicKey) importer).ToECDH();
CngKey ecdsaKey = ((ECDSAPublicKey) importer).ToECDSA();

// ...
```

In case you don't know what algorithm the key you are importing is intended for, you can find out by using the `Algorithm` field of your importer object.

## License
This library is licensed under the BSD-3-clause license found inside the LICENSE file in this source tree's root directory.

## Binaries
In case you don't want to compile the library yourself you may download the DLL-file found inside the Deploy sub-directory of this source tree.

## Contact
If you would like to get in touch or if you have any question regarding this project, feel write to drop me a message at developers [at] blackypaw.com
