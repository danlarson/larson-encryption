namespace LarsonTech.Encryption.Test;

[TestClass]
public class SimpleAesEncryptorTest
{
    [TestMethod]
    public void AES_BasicEncryption()
    {
        string hello = "hello world";//Guid.NewGuid().ToString();

        SimpleAesEncryptor enc = new SimpleAesEncryptor();
        var encrypted = enc.Encrypt(Encoding.UTF8.GetBytes(hello));

        Assert.IsFalse(Encoding.UTF8.GetString(encrypted) == hello);

        var dec = enc.DecryptString(encrypted);
        Assert.AreEqual(hello, dec);

    }

    [TestMethod]
    public void AES_EncryptionsAreUniqueForSameData()
    {
        string hello = Guid.NewGuid().ToString();

        SimpleAesEncryptor enc = new SimpleAesEncryptor();

        var estring = Encoding.UTF8.GetString(enc.Encrypt(Encoding.UTF8.GetBytes(hello)));
        var estring2 = Encoding.UTF8.GetString(enc.Encrypt(Encoding.UTF8.GetBytes(hello)));
        var estring3 = Encoding.UTF8.GetString(enc.Encrypt(Encoding.UTF8.GetBytes(hello)));

        Assert.IsFalse(estring == null);
        Assert.IsFalse(estring == hello);
        Assert.IsFalse(estring == estring2);
        Assert.IsFalse(estring == estring3);
        Assert.IsFalse(estring2 == estring3);
    }
}