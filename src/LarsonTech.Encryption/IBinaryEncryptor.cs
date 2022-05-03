namespace Bct.Common.Encryption
{
    public interface IBinaryEncryptor
    {
        byte[] DecryptBytes(byte[] encryptedValue);
        byte[] EncryptBytes(byte[] data);
    }
}