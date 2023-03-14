namespace LarsonTech.Encryption;
public class RsaEncryptor : IBinaryEncryptor, IDisposable
{
    private X509Certificate2 Certificate { get; }

    public RsaEncryptor(X509Certificate2 cert)
    {
        Certificate = cert ?? throw new ArgumentNullException(nameof(cert));
    }

    public byte[] DecryptBytes(byte[] encryptedValue)
    {
        using var rsa = Certificate.GetRSAPrivateKey();
        return rsa?.Decrypt(encryptedValue, RSAEncryptionPadding.OaepSHA512) ?? Array.Empty<byte>();
    }

    public byte[] EncryptBytes(byte[] data)
    {
        using var rsa = Certificate.GetRSAPublicKey();
        if (rsa == null)
            throw new InvalidOperationException();

        return rsa.Encrypt(data,  RSAEncryptionPadding.OaepSHA512);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        ((IDisposable)Certificate).Dispose();
    }
}