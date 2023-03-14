namespace LarsonTech.Encryption;

/// <summary>
///     A general purpose AES Encryption class.
/// </summary>
public abstract class AesEncryptor : IBinaryEncryptor
{
    public const int KeyLength = 32;
    private readonly byte[] _key;

    protected AesEncryptor(byte[] key)
    {
        _key = key;
    }

    byte[] IBinaryEncryptor.DecryptBytes(byte[] encryptedValue)
    {
        return Decrypt(encryptedValue);
    }

    byte[] IBinaryEncryptor.EncryptBytes(byte[] data)
    {
        return Encrypt(data);
    }

    protected static byte[] CreateCryptographicKey()
    {
        return CryptoUtility.CreateCryptographicKey(KeyLength);
    }

    public string DecryptString(byte[] input)
    {
        var decryptedBytes = Decrypt(input);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public byte[] EncryptString(string toEncrypt)
    {
        if (string.IsNullOrEmpty(toEncrypt))
            return Array.Empty<byte>();

        var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);
        return Encrypt(toEncryptBytes);
    }

    public byte[] Encrypt(byte[] toEncryptBytes)
    {
        return Encrypt(_key, toEncryptBytes);
    }

    public static byte[] Encrypt(byte[] encryptionKey, byte[] toEncryptBytes)
    {
        if (encryptionKey == null || encryptionKey.Length == 0) throw new ArgumentException("encryptionKey");

        using var aes = Aes.Create();
        aes.Key = encryptionKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        aes.GenerateIV();
        var iv = aes.IV;
        var encrypter = aes.CreateEncryptor(aes.Key, iv);
        try
        {
            MemoryStream? cipherStream = null;
            try
            {
                cipherStream = new MemoryStream();
                CryptoStream tCryptoStream = null;
                try
                {
                    tCryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write);
                    using var tBinaryWriter = new BinaryWriter(tCryptoStream);
                    //Prepend IV to data
                    cipherStream.Write(iv, 0, iv.Length);
                    tBinaryWriter.Write(toEncryptBytes);
                    tCryptoStream.FlushFinalBlock();
                }
                finally
                {
                    tCryptoStream?.Dispose();
                }

                return cipherStream.ToArray();
            }
            finally
            {
                cipherStream?.Dispose();
            }
        }
        finally
        {
            encrypter.Dispose();
        }
    }

    public byte[] Decrypt(byte[]? input)
    {
        if (input == null || input.Length == 0)
            return Array.Empty<byte>();

        return Decrypt(_key, input);
    }

    public static byte[] Decrypt(byte[] encryptionKey, byte[]? input)
    {
        if (input == null || input.Length == 0)
            return Array.Empty<byte>();

        using var aes = Aes.Create();
        aes.Key = encryptionKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;


        //get first 16 bytes of IV and use it to decrypt
        var iv = new byte[16];
        Array.Copy(input, 0, iv, 0, iv.Length);

        MemoryStream? ms = null;
        try
        {
            ms = new MemoryStream();
            try
            {
                var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Write);
                using var binaryWriter = new BinaryWriter(cs);
                // Decrypt Cipher Text from Message
                binaryWriter.Write(
                    input,
                    iv.Length,
                    input.Length - iv.Length
                );
            }
            finally
            {
                ms.Dispose();
            }

            return ms.ToArray();
        }
        finally
        {
            ms?.Dispose();
        }
    }
}