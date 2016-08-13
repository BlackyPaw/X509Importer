//
// (c) 2016, BlackyPaw
// This code is licensed under the BSD-3-clause license found in the LICENSE file of this source tree's root directory
//

using System;
using System.IO;
using System.Security.Cryptography;

namespace BlackyPaw.Crypto
{
    /// <summary>
    /// Represents a RSA public key which has been imported using X509EncodedPublicKeyImporter.Import(...).
    /// </summary>
    public class RSAPublicKeyImporter : X509EncodedPublicKeyImporter
    {

        private CngKey _cngKey;

        public override X509Algorithm Algorithm
        {
            get
            {
                return X509Algorithm.RSA;
            }
        }

        internal RSAPublicKeyImporter()
        {

        }

        /// <summary>
        /// Imports a RSA public key from the given DER-encoded BIT STRING.
        /// </summary>
        /// 
        /// <param name="input">The stream to read the DER-encoded BIT STRING from</param>
        protected override void ImportFromDERBitString(Stream input)
        {
            // subjectPublicKey must be a BIT STRING:
            if (input.ReadByte() != X509EncodedPublicKeyImporter.DER_TAG_BIT_STRING)
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is missing)");
            }

            // Skip length of BIT STRING (not required any further)
            X509EncodedPublicKeyImporter.ReadASN1TagLength( input );
            input.ReadByte(); // Skip UnusedBits Indicator

            // RSA Key must be wrapped inside another SEQUENCE:
            if ( input.ReadByte() != X509EncodedPublicKeyImporter.DER_TAG_SEQUENCE )
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
            }

            X509EncodedPublicKeyImporter.ReadASN1TagLength(input);

            // SEQUENCE in turn must contain two integers - modulus and public exponent:


            // Modulus:
            if ( input.ReadByte() != X509EncodedPublicKeyImporter.DER_TAG_INTEGER )
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
            }

            int modulusLength = X509EncodedPublicKeyImporter.ReadASN1TagLength(input);
            byte leadingByte = (byte) input.ReadByte();
            byte[] modulus;
            if ( leadingByte == 0x00 )
            {
                modulus = new byte[modulusLength - 1];
                if ( input.Read( modulus, 0, modulusLength - 1 ) != modulusLength - 1 )
                {
                    throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
                }
            }
            else
            {
                modulus = new byte[modulusLength];
                modulus[0] = leadingByte;
                if (input.Read(modulus, 1, modulusLength - 1) != modulusLength - 1)
                {
                    throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
                }
            }


            // Public Exponent:
            if ( input.ReadByte() != X509EncodedPublicKeyImporter.DER_TAG_INTEGER )
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
            }

            int publicExponentLength = X509EncodedPublicKeyImporter.ReadASN1TagLength(input);
            leadingByte = (byte)input.ReadByte();
            byte[] publicExponent;
            if (leadingByte == 0x00)
            {
                publicExponent = new byte[publicExponentLength - 1];
                if (input.Read(publicExponent, 0, publicExponentLength - 1) != publicExponentLength - 1)
                {
                    throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
                }
            }
            else
            {
                publicExponent = new byte[publicExponentLength];
                publicExponent[0] = leadingByte;
                if (input.Read(publicExponent, 1, publicExponentLength - 1) != publicExponentLength - 1)
                {
                    throw new IOException("DER container does not contain SubjectPublicKeyInfo (RSA public key data is corrupt)");
                }
            }



            // Finally - that's all information we needed and also all that is encoded according to RFC3279
            // Now assemble our CngKey and we're finally done:

            byte[] rsaBlob = ConvertToGenericPublicKeyBlob(modulus, publicExponent);
            this._cngKey = CngKey.Import(rsaBlob, CngKeyBlobFormat.GenericPublicBlob);
        }

        /// <summary>
        /// Converts the given raw RSA public key information to a BCRYPT BLOB which may be imported by CngKey's
        /// Import(...) method.
        /// </summary>
        /// 
        /// <param name="modulus">The RSA Key's modulus</param>
        /// <param name="publicExponent">The RSA Key's public exponent</param>
        /// <returns>The created BLOB</returns>
        private static byte[] ConvertToGenericPublicKeyBlob( byte[] modulus, byte[] publicExponent )
        {
            // Format as BLOB according to https://msdn.microsoft.com/en-us/library/windows/desktop/aa375531(v=vs.85).aspx

            int bitLength = modulus.Length << 3;

            const int BLOB_HEADER_SIZE = 24;
            byte[] rsaBlob = new byte[BLOB_HEADER_SIZE + modulus.Length + publicExponent.Length];

            rsaBlob[0] = 0x52;      // BCRYPT_MAGIC
            rsaBlob[1] = 0x53;
            rsaBlob[2] = 0x41;
            rsaBlob[3] = 0x31;

            // BIT LENGTH:
            writeIntegerToByteArrayBE(rsaBlob, 4, bitLength);
            // PUBLIC EXPONENT LENGTH:
            writeIntegerToByteArrayBE(rsaBlob, 8, publicExponent.Length);
            // MODULUS LENGTH:
            writeIntegerToByteArrayBE(rsaBlob, 12, modulus.Length);

            // Leave cbPrime1 and cbPrime2 as zeroes (not required for public keys)

            // Copy modulus and public exponent over to RSA blob:
            Array.Copy(publicExponent, 0, rsaBlob, BLOB_HEADER_SIZE, publicExponent.Length);
            Array.Copy(modulus, 0, rsaBlob, BLOB_HEADER_SIZE + publicExponent.Length, modulus.Length);

            // Done:
            return rsaBlob;
        }

        /// <summary>
        /// Writes the given integer value into the specified buffer at the given offset.
        /// </summary>
        /// 
        /// <param name="buffer">The buffer into which to write the integer value</param>
        /// <param name="offset">The offset at which to write the integer value into the given buffer</param>
        /// <param name="value">The value to write into the given buffer</param>
        private static void writeIntegerToByteArrayBE( byte[] buffer, int offset, int value )
        {
            byte[] bytes = BitConverter.GetBytes(value);
            Array.Copy(bytes, 0, buffer, offset, bytes.Length);
        }

        /// <summary>
        /// Converts this RSA public key to a CngKey which may be used in conjunction with RSACng.
        /// </summary>
        /// 
        /// <returns>The converted CngKey instance</returns>
        public CngKey ToCngKey()
        {
            return this._cngKey;
        }

    }
}
