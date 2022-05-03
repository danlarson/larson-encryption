using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Bct.Common.Encryption.Test
{
    [TestClass]
    public class CryptoUtilityTest
    {
        [TestMethod]
        public void RNGCryptoServiceProvider_TestKeyGen()
        {
            var key = CryptoUtility.CreateCryptograhicKey(32);
            string skey = Convert.ToBase64String(key);
            Assert.IsNotNull(skey);
        }
    }
}
