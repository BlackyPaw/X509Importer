//
// (c) 2016, BlackyPaw
// This code is licensed under the BSD-3-clause license found in the LICENSE file of this source tree's root directory
//

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace BlackyPaw.Crypto
{
    /// <summary>
    /// Helper class which may be used to import public keys which have been encoded according to the X.509 SubjectPublicKeyInfo format
    /// such as public keys encoded using Java. This class supports importing ECDH/ECDSA keys of key sizes 256-Bit, 384-Bit and 521-Bit
    /// as well as RSA Public Keys of arbitrary size. In order to retrieve the actual CngKey object that was imported one will have to
    /// check the Algorithm field of the imported X509EncodedPublicKeyImporter object and cast it to  one of its subclasses accordingly.
    /// Those subclasses provide conversion methods which may be used to retrieve an actual CngKey.
    /// </summary>
    public abstract class X509EncodedPublicKeyImporter
    {

        internal const byte DER_TAG_INTEGER = 0x02;
        internal const byte DER_TAG_BIT_STRING = 0x03;
        internal const byte DER_TAG_OCTET_STRING = 0x04;
        internal const byte DER_TAG_OBJECT_IDENTIFIER = 0x06;
        internal const byte DER_TAG_SEQUENCE = 0x30;


        // As defined in https://tools.ietf.org/html/rfc3279#section-2.3.1
        private static readonly byte[] OBJECT_IDENTIFIER_RSAENCRYPT = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

        // As defined in https://tools.ietf.org/html/rfc3279#section-2.3.5
        private static readonly byte[] OBJECT_IDENTIFIER_ECDH_ECDSA = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

        /// <summary>
        /// Imports a DER-encoded public key which contains data as specified by the X.509 SubjectPublicKeyInfo standard.
        /// </summary>
        /// 
        /// <exception cref="System.IO.IOException">Thrown if an error occured whilst reading the DER encoded public key from the given stream</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown if the given key could not be imported although if might have been valid</exception>
        /// <param name="input">The stream to read the DER-encoded public key from</param>
        /// <returns>The imported public key</returns>
        public static X509EncodedPublicKeyImporter ImportFromDER(Stream input)
        {
            // Must start with a TAG_SEQUENCE
            if (input.ReadByte() != DER_TAG_SEQUENCE)
            {
                // Invalid DER header
                throw new IOException("Invalid DER header found");
            }

            // Read entire length from stream:
            ReadASN1TagLength(input);

            // Read all remaining bytes from stream and pass on to actual decoding:

            // First TAG in a valid SubjectPublicKeyInfo X.509 encoding must be a TAG_SEQUENCE (algorithm information):
            if (input.ReadByte() != DER_TAG_SEQUENCE)
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo");
            }

            X509EncodedPublicKeyImporter pubkey = null;

            int algorithmInformationLength = ReadASN1TagLength(input);
            long previousPosition = input.Position;
            {
                // First child TAG should be a TAG_OBJECT_IDENTIFIER:
                if (input.ReadByte() != DER_TAG_OBJECT_IDENTIFIER)
                {
                    throw new IOException("DER container does not contain SubjectPublicKeyInfo (algorithm information missing)");
                }

                int oidLength = ReadASN1TagLength(input);
                byte[] oidRaw = new byte[oidLength];
                if (input.Read(oidRaw, 0, oidLength) != oidLength)
                {
                    throw new IOException("DER container does not contain SubjectPublicKeyInfo (algorithm information corrupt)");
                }

                // Detect algorithm:
                if (OBJECT_IDENTIFIER_RSAENCRYPT.SequenceEqual(oidRaw))
                {
                    pubkey = new RSAPublicKeyImporter();
                }
                else if (OBJECT_IDENTIFIER_ECDH_ECDSA.SequenceEqual(oidRaw))
                {
                    pubkey = new ECDSAPublicKeyImporter();
                }

                // Skip remaining bytes of algorithm information:
                input.Seek(algorithmInformationLength - (input.Position - previousPosition), SeekOrigin.Current);
            }

            // If we could not instantiate a proper key instance this means the respective algorithm is not supported:
            if (pubkey == null)
            {
                throw new CryptographicException("Could not parse public key: unsupported algorithm");
            }

            pubkey.ImportFromDERBitString(input);
            return pubkey;
        }

        /// <summary>
        /// Reads the length of a DER Tag from the given input stream assuming it is encoded using the definite ASN.1 length encoding.
        /// For further information on how such length values are encoded, see http://luca.ntop.org/Teaching/Appunti/asn1.html Section
        /// 3.1.
        /// 
        /// This method does not support Tag lengths which require more than 4 bytes (i.e. keys which are larger than 2^31 bytes).
        /// </summary>
        /// 
        /// <exception cref="System.IO.IOException">Thrown if the length could not be read because it exceeds the 4 byte limit or the stream did not read enough bytes</exception>
        /// <param name="input">The input stream to read the ASN.1 encoded length from</param>
        /// <returns>The decoded length as an integer</returns>
        protected static int ReadASN1TagLength(Stream input)
        {
            int totalLength = input.ReadByte();
            if ((totalLength & 0x80) != 0)
            {
                int trailing = totalLength & 0xF;
                if (trailing > 4)
                {
                    // Key exceeds 4-Byte Length? Impressive...
                    throw new IOException("DER Key is too large to be imported");
                }

                byte[] lengthBytes = new byte[4];
                if (input.Read(lengthBytes, 4 - trailing, trailing) != trailing)
                {
                    throw new IOException("ASN.1 encoded tag length could not be read");
                }
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(lengthBytes);
                }
                totalLength = BitConverter.ToInt32(lengthBytes, 0);
            }
            return totalLength;
        }

        // Properties:

        /// <summary>
        /// The algorithm this public key is intended for.
        /// </summary>
        public abstract X509Algorithm Algorithm
        {
            get;
        }

        /// <summary>
        /// Hidden from the outside. Use ImportFromDER(...) instead.
        /// </summary>
        internal X509EncodedPublicKeyImporter()
        {
            // Hide form the outside world
        }

        /// <summary>
        /// Imports the actual public key data whose format depends on the algorithm specified by its Object Identifier
        /// in the DER-encoded raw data.
        /// </summary>
        /// 
        /// <param name="input">The stream to read the actual public key data from</param>
        protected abstract void ImportFromDERBitString(Stream input);

    }
}
