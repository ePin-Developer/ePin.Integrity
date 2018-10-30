using DataAccess.Models;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace ePin.IntegrityMonitor
{
    public class DigitallySigned
    {
        private static FileIntegrity IsSigned(FileIntegrity file)
        {
            string filePath = file.Filename;

            if (!File.Exists(filePath))
            {
                Console.WriteLine("File not found");
                file.ErrorMessage = "File not found";
                return file;
            }

            X509Certificate2 theCertificate;

            try
            {
                X509Certificate theSigner = X509Certificate.CreateFromSignedFile(filePath);
                theCertificate = new X509Certificate2(theSigner);
            }
            catch (Exception ex)
            {
                Console.WriteLine("No digital signature found: " + ex.Message);

                file.ErrorMessage = ("No digital signature found: " + ex.Message);
                return file;
            }

            bool chainIsValid = false;

            /*
            *
            * This section will check that the certificate is from a trusted authority IE
            * not self-signed.
            *
            */

            var theCertificateChain = new X509Chain();

            theCertificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

            /*
             *
             * Using .Online here means that the validation WILL CALL OUT TO THE INTERNET
             * to check the revocation status of the certificate. Change to .Offline if you
             * don't want that to happen.
             */

            theCertificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;

            theCertificateChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);

            theCertificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            chainIsValid = theCertificateChain.Build(theCertificate);

            if (chainIsValid)
            {
                file.PublisherInformation = theCertificate.SubjectName.Name;
                file.ValidFrom = theCertificate.GetEffectiveDateString();
                file.ValidTo = theCertificate.GetExpirationDateString();
                file.IssuedBy = theCertificate.GetExpirationDateString();

                Console.WriteLine("Publisher Information : " + theCertificate.SubjectName.Name);
                Console.WriteLine("Valid From: " + theCertificate.GetEffectiveDateString());
                Console.WriteLine("Valid To: " + theCertificate.GetExpirationDateString());
                Console.WriteLine("Issued By: " + theCertificate.Issuer);
            }
            else
            {
                Console.WriteLine("Chain Not Valid (certificate is self-signed)");
                file.ErrorMessage = "Chain Not Valid(certificate is self - signed)";
                return file;
            }
            return file;
        }
    }
}