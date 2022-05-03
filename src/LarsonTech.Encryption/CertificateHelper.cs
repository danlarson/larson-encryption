using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Bct.Common.Encryption
{
    public static class CertificateHelper
    {
        public static X509Certificate2? LoadCertificateByThumbprint(string thumbprint)
        {
            // on linux, currentuser is the only valid store. 
            var cert = LoadCertificateByThumbprint(StoreName.My, StoreLocation.CurrentUser, thumbprint);
            if (cert == null)
            {
                try
                {
                    LoadCertificateByThumbprint(StoreName.My, StoreLocation.LocalMachine, thumbprint);
                }
                catch
                {
                    Debug.WriteLine("Certificate not found");
                }
            }

            return cert;
        }

        public static X509Certificate2? LoadCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            if (certCollection.Count > 0)
                return certCollection[0];

            return (from cert in store.Certificates.Cast<X509Certificate2>().Where(x => x.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase))
                where cert.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase) select new X509Certificate2(cert)).FirstOrDefault();
        }
    }
}