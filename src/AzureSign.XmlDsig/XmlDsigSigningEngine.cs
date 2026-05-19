using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using AzureSign.Engines;
using Microsoft.Extensions.Logging;

namespace AzureSign.XmlDsig
{
    public sealed class XmlDsigSigningEngine : ISigningEngine
    {
        public string Name => "XmlDsig";

        public string Description => "Signs XML files using XML Digital Signatures (XMLDSig) via Azure Key Vault.";

        public IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".xml", ".svg", ".xhtml" };

        public Task<bool> SignAsync(SigningRequest request, CancellationToken cancellationToken = default)
            => Task.Run(() => Sign(request), cancellationToken);

        private static bool Sign(SigningRequest request)
        {
            if (request.Key is not RSA rsa)
            {
                request.Logger.LogError("XmlDsig signing requires an RSA key; got {KeyType}.", request.Key?.GetType().Name);
                return false;
            }

            try
            {
                var doc = new XmlDocument { PreserveWhitespace = true };
                doc.Load(request.FilePath);

                if (doc.DocumentElement is null)
                {
                    request.Logger.LogError("XML file has no root element: {FilePath}", request.FilePath);
                    return false;
                }

                var signedXml = new SignedXml(doc) { SigningKey = rsa };
                signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
                signedXml.SignedInfo.SignatureMethod = GetSignatureMethod(request.HashAlgorithm);

                var reference = new Reference
                {
                    Uri = "",
                    DigestMethod = GetDigestMethod(request.HashAlgorithm),
                };
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigExcC14NTransform());
                signedXml.AddReference(reference);

                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(request.Certificate, X509IncludeOption.EndCertOnly));
                signedXml.KeyInfo = keyInfo;

                signedXml.ComputeSignature();

                var signatureNode = signedXml.GetXml();
                doc.DocumentElement.AppendChild(doc.ImportNode(signatureNode, true));
                doc.Save(request.FilePath);

                return true;
            }
            catch (Exception ex)
            {
                request.Logger.LogError(ex, "Failed to sign {FilePath} with XmlDsig.", request.FilePath);
                return false;
            }
        }

        private static string GetSignatureMethod(HashAlgorithmName algorithm) => algorithm.Name switch
        {
            "SHA256" => SignedXml.XmlDsigRSASHA256Url,
            "SHA384" => SignedXml.XmlDsigRSASHA384Url,
            "SHA512" => SignedXml.XmlDsigRSASHA512Url,
            _ => SignedXml.XmlDsigRSASHA256Url,
        };

        private static string GetDigestMethod(HashAlgorithmName algorithm) => algorithm.Name switch
        {
            "SHA256" => SignedXml.XmlDsigSHA256Url,
            "SHA384" => SignedXml.XmlDsigSHA384Url,
            "SHA512" => SignedXml.XmlDsigSHA512Url,
            _ => SignedXml.XmlDsigSHA256Url,
        };
    }
}
