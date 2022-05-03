using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Bct.Common.Encryption
{
    public class RsaEncryptor : IBinaryEncryptor, IDisposable
    {
        private X509Certificate2 Certificate { get; }

        public RsaEncryptor(X509Certificate2 cert)
        {
            Certificate = cert ?? throw new ArgumentNullException();
        }

        public byte[] DecryptBytes(byte[] encryptedValue)
        {
            using var RSA = Certificate.GetRSAPrivateKey();
            return RSA.Decrypt(encryptedValue, RSAEncryptionPadding.Pkcs1);
        }

        public byte[] EncryptBytes(byte[] data)
        {
            using var rsa = Certificate.GetRSAPublicKey();
            if (rsa == null)
                throw new InvalidOperationException();
            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        public void Dispose()
        {
            ((IDisposable)Certificate).Dispose();
        }
    }
}
