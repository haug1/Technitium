using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DnsServerCore.Configuration
{
    internal sealed record Pkcs12Certificate(SslStreamCertificateContext Context, DateTime LastModified, string FileHash)
    {
        internal static Pkcs12Certificate Read(string tlsCertificatePath, string tlsCertificatePassword, X509KeyStorageFlags keyStorage)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("TLS certificate file does not exist: " + tlsCertificatePath);

            switch (Path.GetExtension(tlsCertificatePath).ToLowerInvariant())
            {
                case ".pfx":
                case ".p12":
                    break;

                default:
                    throw new ArgumentException("TLS certificate file must be PKCS #12 formatted with .pfx or .p12 extension: " + tlsCertificatePath);
            }

            byte[] data = File.ReadAllBytes(tlsCertificatePath);
            X509Certificate2Collection certificateCollection = X509CertificateLoader.LoadPkcs12Collection(data, tlsCertificatePassword, keyStorage);
            X509Certificate2 serverCertificate = null;

            foreach (X509Certificate2 certificate in certificateCollection)
            {
                if (certificate.HasPrivateKey)
                {
                    serverCertificate = certificate;
                    break;
                }
            }

            if (serverCertificate is null)
                throw new ArgumentException("TLS certificate file must contain a certificate with private key.");

            SslStreamCertificateContext certificateContext = SslStreamCertificateContext.Create(serverCertificate, certificateCollection,
                offline: keyStorage == X509KeyStorageFlags.EphemeralKeySet);
            return new Pkcs12Certificate(certificateContext, fileInfo.LastWriteTimeUtc, Convert.ToHexString(SHA256.HashData(data)));
        }
    }
}
