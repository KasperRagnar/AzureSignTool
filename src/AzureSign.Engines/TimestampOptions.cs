using System.Security.Cryptography;

namespace AzureSign.Engines
{
    public sealed class TimestampOptions
    {
        public static TimestampOptions None { get; } = new TimestampOptions(null, default, TimestampKind.None);

        public string? Url { get; }
        public HashAlgorithmName DigestAlgorithm { get; }
        public TimestampKind Kind { get; }

        public TimestampOptions(string? url, HashAlgorithmName digestAlgorithm, TimestampKind kind)
        {
            Url = url;
            DigestAlgorithm = digestAlgorithm;
            Kind = kind;
        }
    }

    public enum TimestampKind
    {
        None,
        Authenticode,
        RFC3161,
    }
}
