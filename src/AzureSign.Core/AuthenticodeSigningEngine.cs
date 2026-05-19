using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AzureSign.Engines;

namespace AzureSign.Core
{
    /// <summary>Signs files using Windows Authenticode via Azure Key Vault.</summary>
    public sealed class AuthenticodeSigningEngine : ISigningEngine
    {
        /// <inheritdoc/>
        public string Name => "Authenticode";

        /// <inheritdoc/>
        public string Description => "Signs files using Windows Authenticode via Azure Key Vault.";

        /// <inheritdoc/>
        public IReadOnlyList<string> SupportedExtensions { get; } = new[]
        {
            ".exe", ".dll", ".sys", ".vxd", ".scr", ".efi",
            ".msi", ".msp", ".msm",
            ".cab",
            ".appx", ".appxbundle", ".msix", ".msixbundle",
            ".ps1", ".psm1",
        };

        /// <inheritdoc/>
        public Task<bool> SignAsync(SigningRequest request, CancellationToken cancellationToken = default)
        {
            var tsConfig = ConvertTimestamp(request.Timestamp);

            using var signer = new AuthenticodeKeyVaultSigner(
                request.Key,
                request.Certificate,
                request.HashAlgorithm,
                tsConfig);

            int result = signer.SignFile(
                request.FilePath,
                request.Description,
                request.DescriptionUrl,
                pageHashing: null,
                request.Logger);

            return Task.FromResult(result == 0);
        }

        private static TimeStampConfiguration ConvertTimestamp(TimestampOptions? options)
        {
            if (options is null || options.Kind == TimestampKind.None)
            {
                return TimeStampConfiguration.None;
            }

            return options.Kind switch
            {
                TimestampKind.RFC3161 => new TimeStampConfiguration(options.Url!, options.DigestAlgorithm, TimeStampType.RFC3161),
                TimestampKind.Authenticode => new TimeStampConfiguration(options.Url!, default, TimeStampType.Authenticode),
                _ => TimeStampConfiguration.None,
            };
        }
    }
}
