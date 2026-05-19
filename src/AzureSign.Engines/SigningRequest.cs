using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AzureSign.Engines
{
    public sealed class SigningRequest
    {
        public string FilePath { get; }
        public AsymmetricAlgorithm Key { get; }
        public X509Certificate2 Certificate { get; }
        public HashAlgorithmName HashAlgorithm { get; }
        public TimestampOptions? Timestamp { get; }
        public string? Description { get; }
        public string? DescriptionUrl { get; }
        public ILogger Logger { get; }

        public SigningRequest(
            string filePath,
            AsymmetricAlgorithm key,
            X509Certificate2 certificate,
            HashAlgorithmName hashAlgorithm,
            TimestampOptions? timestamp = null,
            string? description = null,
            string? descriptionUrl = null,
            ILogger? logger = null)
        {
            FilePath = filePath;
            Key = key;
            Certificate = certificate;
            HashAlgorithm = hashAlgorithm;
            Timestamp = timestamp;
            Description = description;
            DescriptionUrl = descriptionUrl;
            Logger = logger ?? NullLogger.Instance;
        }
    }
}
