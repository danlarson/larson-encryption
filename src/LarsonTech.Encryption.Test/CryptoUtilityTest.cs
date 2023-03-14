namespace LarsonTech.Encryption.Test;

[TestClass]
public class CryptoUtilityTest
{
    [TestMethod]
    public void RNGCryptoServiceProvider_TestKeyGen()
    {
        var key = CryptoUtility.CreateCryptographicKey(32);
        var skey = Convert.ToBase64String(key);
        Assert.IsNotNull(skey);
    }
}

