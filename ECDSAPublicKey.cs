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
    /// Represents an ECDH / ECDSA public key which has been imported using X509EncodedPublicKeyImporter.Import(...).
    /// </summary>
    public class ECDSAPublicKeyImporter : X509EncodedPublicKeyImporter
    {
        private static readonly byte[] BCRYPT_MAGIC_NUMBER_ECDH256 = new byte[] { 0x45, 0x43, 0x4B, 0x31 };
        private static readonly byte[] BCRYPT_MAGIC_NUMBER_ECDH384 = new byte[] { 0x45, 0x43, 0x4B, 0x33 };
        private static readonly byte[] BCRYPT_MAGIC_NUMBER_ECDH521 = new byte[] { 0x45, 0x43, 0x4B, 0x35 };

        private static readonly byte[] BCRYPT_MAGIC_NUMBER_ECDSA256 = new byte[] { 0x45, 0x43, 0x53, 0x31 };
        private static readonly byte[] BCRYPT_MAGIC_NUMBER_ECDSA384 = new byte[] { 0x45, 0x43, 0x53, 0x33 };
        private static readonly byte[] BCRYPT_MAGIC_NUMBER_ECDSA521 = new byte[] { 0x45, 0x43, 0x53, 0x35 };

        private X509Algorithm _algorithm;
        private byte[] _eccPoint;

        public override X509Algorithm Algorithm
        {
            get
            {
                return _algorithm;
            }
        }

        internal ECDSAPublicKeyImporter()
        {

        }

        /// <summary>
        /// Converts this Elliptic-Curve key to an Elliptic-Curve-Diffie-Hellman key. For converting this key to an Elliptic-Curve-Digital-Signature-Algorithm key instead
        /// use ToECDSA().
        /// </summary>
        /// 
        /// <returns>A CngKey ready for use with ECDiffieHellmanCng</returns>
        public CngKey ToECDH()
        {
            byte[] magic = (this._algorithm == X509Algorithm.ECDH_ECDSA_256 ? BCRYPT_MAGIC_NUMBER_ECDH256 : (this._algorithm == X509Algorithm.ECDH_ECDSA_384 ? BCRYPT_MAGIC_NUMBER_ECDH384 : BCRYPT_MAGIC_NUMBER_ECDH521));
            return this.ToCngKey(magic);
        }

        /// <summary>
        /// Converts this Elliptic-Curve key to an Elliptic-Curve-Digital-Signature-Algorithm key. For converting this key to an Elliptic-Curve-Diffie-Hellman key instead
        /// use ToECDH().
        /// </summary>
        /// 
        /// <returns>A CngKey ready for use with ECDsaCng</returns>
        public CngKey ToECDSA()
        {
            byte[] magic = (this._algorithm == X509Algorithm.ECDH_ECDSA_256 ? BCRYPT_MAGIC_NUMBER_ECDSA256 : (this._algorithm == X509Algorithm.ECDH_ECDSA_384 ? BCRYPT_MAGIC_NUMBER_ECDSA384 : BCRYPT_MAGIC_NUMBER_ECDSA521));
            return this.ToCngKey(magic);
        }

        /// <summary>
        /// Imports the raw ECC public key data from a DER-encoded BIT STRING.
        /// </summary>
        /// 
        /// <param name="input">The stream to read the DER-encoded BIT STRING from</param>
        protected override void ImportFromDERBitString( Stream input )
        {
            // subjectPublicKey must be a BIT STRING:
            if ( input.ReadByte() != X509EncodedPublicKeyImporter.DER_TAG_BIT_STRING )
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (ECDSA public key data is missing)");
            }

            // Read Length of BIT STRING (required for determining ECC Point Size):
            int eccPointLength = X509EncodedPublicKeyImporter.ReadASN1TagLength(input);
            input.ReadByte(); // Skip UnusedBits Indicator

            // As defined in https://tools.ietf.org/html/rfc3279#section-2.3.5 - what follows must be an OCTET STRING which
            // has infinite length encoding, i.e. reaches up to the end of the enclosing BIT STRING:
            if ( input.ReadByte() != X509EncodedPublicKeyImporter.DER_TAG_OCTET_STRING )
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (ECDSA public key data is corrupt)");
            }

            // The length of this indefinite OCTET STRING is equal to the difference between the length of the enclosing
            // BIT STRING minus the two bytes for the UnusedIndicator and the OCTET STRING TagID:
            eccPointLength -= 2;

            byte[] eccPoint = new byte[eccPointLength];
            if ( input.Read( eccPoint, 0, eccPointLength ) != eccPointLength )
            {
                throw new IOException("DER container does not contain SubjectPublicKeyInfo (ECDSA public key data is corrupt)");
            }

            // Finally! We now have the ECC Point data - hopefully uncompressed, because as RFC3279 states, implementation MUST only
            // implement support for uncompressed keys and MAY support compressed keys - which I simply don't because I could not
            // even find a hint at what is meant by compressed data ._.
            //
            // My wild guess was that they simply trim leading zeroes in order to shorten smaller point coordinates but I honestly
            // don't know for sure (I strongly doubt they would use an actual compression algorithm for those lumpy hundred somewhat
            // bytes):

            switch ( eccPointLength )
            {
                case 64:
                    this._algorithm = X509Algorithm.ECDH_ECDSA_256;
                    break;
                case 96:
                    this._algorithm = X509Algorithm.ECDH_ECDSA_384;
                    break;
                case 130:
                    this._algorithm = X509Algorithm.ECDH_ECDSA_521;
                    break;
                default:
                    throw new IOException("Could not parse ECDH / ECDSA public key: unsupported key-size or compressed key format");
            }

            // Done, phew, that was quite an act :D!
            this._eccPoint = eccPoint;
        }

        /// <summary>
        /// Creates a raw BCRYPT ECC PUBLIC KEY BLOB using the given BCRYPT magic value and passes it to CngKey's Import(...) function to obtain
        /// an actual CngKey instance.
        /// </summary>
        /// 
        /// <param name="magic">The magic value to put into the ECC PUBLIC KEY BLOB (must be one of the constants defined in this class)</param>
        /// <returns>The created CngKey instance</returns>
        private CngKey ToCngKey( byte[] magic )
        {
            byte[] eccBlob = new byte[8 + this._eccPoint.Length];

            Array.Copy(magic, 0, eccBlob, 0, 4);

            byte keyLength = (byte) (this._algorithm == X509Algorithm.ECDH_ECDSA_256 ? 0x20 : (this._algorithm == X509Algorithm.ECDH_ECDSA_384 ? 0x30 : 0x41));
            eccBlob[4] = keyLength;

            Array.Copy(this._eccPoint, 0, eccBlob, 8, this._eccPoint.Length);

            return CngKey.Import(eccBlob, CngKeyBlobFormat.EccPublicBlob);
        }

    }
}
