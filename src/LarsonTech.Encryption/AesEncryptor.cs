namespace LarsonTech.Encryption;

/// <summary>
/// A general purpose AES Encryption class. 
/// </summary>
public abstract class AesEncryptor : IBinaryEncryptor
{
    private readonly byte[] _key;

    protected AesEncryptor(byte[] key)
    {
        _key = key;
    }

    public const int KeyLength = 32;

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
        if (encryptionKey == null || encryptionKey.Length == 0) 
            throw new ArgumentException("Encryption key is out of range", nameof(encryptionKey));

        using var aes = Aes.Create();
        aes.Key = encryptionKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        aes.GenerateIV();
        var iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(aes.Key, iv);
        using var cipherStream = new MemoryStream();
        using var tCryptoStream = new CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write);
        using var tBinaryWriter = new BinaryWriter(tCryptoStream);

        //Prepend IV to data
        cipherStream.Write(iv, 0, iv.Length);
        tBinaryWriter.Write(toEncryptBytes);
        tBinaryWriter.Flush();
        tCryptoStream.FlushFinalBlock();

        return cipherStream.ToArray();
    }

    public byte[] Decrypt(byte[]? input)
    {
        if (input == null || input.Length == 0)
            return Array.Empty<byte>();

        return Decrypt(this._key, input);
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

        using var ms = new MemoryStream();

        var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Write);
        using var binaryWriter = new BinaryWriter(cs);
        //Decrypt Cipher Text from Message
        binaryWriter.Write(
            input,
            iv.Length,
            input.Length - iv.Length
            );
        binaryWriter.Flush();
        return ms.ToArray();
    }

    byte[] IBinaryEncryptor.DecryptBytes(byte[] encryptedValue)
    {
        return this.Decrypt(encryptedValue);
    }

    byte[] IBinaryEncryptor.EncryptBytes(byte[] data)
    {
        return this.Encrypt(data);
    }
}