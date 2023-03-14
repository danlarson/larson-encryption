namespace LarsonTech.Encryption.Test;

[TestClass]
public class RsaEncryptorTest
{
    [TestMethod]
    public void RSA_BasicEncryption()
    {
        var thumb = TestConfig.Instance.Thumbprint;

        if (string.IsNullOrEmpty(thumb))
            Assert.Inconclusive("A test cert was not configured. Go fish!");

        thumb = thumb.Replace(" ", string.Empty);
        var cert = CertificateHelper.LoadCertificateByThumbprint(thumb);
        try
        {
            Assert.IsNotNull(cert);
        }
        catch
        {
            Assert.Inconclusive("Couldn't load the test cert. Go fish!");
        }
        var hello = Guid.NewGuid().ToString();

        var enc = new RsaEncryptor(cert);

        var e = enc.EncryptBytes(Encoding.UTF8.GetBytes(hello));
        var s = Encoding.UTF8.GetString(enc.DecryptBytes(e));

        Assert.AreEqual(s, hello);

    }
}