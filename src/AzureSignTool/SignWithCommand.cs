#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using AzureSign.Core;
using AzureSign.Engines;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using XenoAtom.CommandLine;

using static AzureSignTool.HRESULT;

namespace AzureSignTool
{
    internal sealed class SignWithCommand : Command
    {
        internal string? KeyVaultUrl { get; set; }
        internal string? KeyVaultClientId { get; set; }
        internal string? KeyVaultClientSecret { get; set; }
        internal string? KeyVaultTenantId { get; set; }
        internal string? KeyVaultCertificate { get; set; }
        internal string? KeyVaultCertificateVersion { get; set; }
        internal string? KeyVaultAccessToken { get; set; }
        internal bool UseManagedIdentity { get; set; }
        internal string? AzureAuthority { get; set; }
        internal string? FileDigestAlgorithm { get; set; } = "SHA256";
        internal string? Rfc3161TimestampUrl { get; set; }
        internal string? TimestampDigestAlgorithm { get; set; } = "SHA256";
        internal string? AuthenticodeTimestampUrl { get; set; }
        internal string? SignDescription { get; set; }
        internal string? SignDescriptionUrl { get; set; }
        internal string? EngineName { get; set; }
        internal string? PluginsDir { get; set; }
        internal string? InputFileList { get; set; }
        internal bool Verbose { get; set; }
        internal bool Quiet { get; set; }
        internal bool ContinueOnError { get; set; }
        internal bool Colors { get; set; }

        public SignWithCommand() : base("sign-with", "Sign files using a plugin signing engine.", null)
        {
            this.Add(new HelpOption());
            this.Add("kvu|azure-key-vault-url=", "The {URL} to an Azure Key Vault.", v => KeyVaultUrl = v);
            this.Add("kvi|azure-key-vault-client-id=", "The Client {ID} to authenticate to the Azure Key Vault.", v => KeyVaultClientId = v);
            this.Add("kvs|azure-key-vault-client-secret=", "The Client Secret to authenticate to the Azure Key Vault.", v => KeyVaultClientSecret = v);
            this.Add("kvt|azure-key-vault-tenant-id=", "The Tenant Id to authenticate to the Azure Key Vault.", v => KeyVaultTenantId = v);
            this.Add("kvc|azure-key-vault-certificate=", "The name of the certificate in Azure Key Vault.", v => KeyVaultCertificate = v);
            this.Add("kvcv|azure-key-vault-certificate-version=", "The version of the certificate in Azure Key Vault to use.", v => KeyVaultCertificateVersion = v);
            this.Add("kva|azure-key-vault-accesstoken=", "The Access Token to authenticate to the Azure Key Vault.", v => KeyVaultAccessToken = v);
            this.Add("kvm|azure-key-vault-managed-identity", "Use the current Azure managed identity.", v => UseManagedIdentity = v is not null);
            this.Add("au|azure-authority=", "The Azure Authority for Azure Key Vault.", v => AzureAuthority = v);
            this.Add("fd|file-digest=", "The digest algorithm to hash the file with.", v => FileDigestAlgorithm = v);
            this.Add("tr|timestamp-rfc3161=", "Specifies the RFC 3161 timestamp server's URL.", v => Rfc3161TimestampUrl = v);
            this.Add("td|timestamp-digest=", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.", v => TimestampDigestAlgorithm = v);
            this.Add("t|timestamp-authenticode=", "Specify the legacy timestamp server's URL.", v => AuthenticodeTimestampUrl = v);
            this.Add("d|description=", "Provide a description of the signed content.", v => SignDescription = v);
            this.Add("du|description-url=", "Provide a URL with more information about the signed content.", v => SignDescriptionUrl = v);
            this.Add("e|engine=", "The name of the signing engine to use. If omitted, the engine is selected by file extension.", v => EngineName = v);
            this.Add("pd|plugins-dir=", "Directory to scan for plugin assemblies. Defaults to 'plugins' next to the executable.", v => PluginsDir = v);
            this.Add("ifl|input-file-list=", "A path to a file that contains a list of files, one per line, to sign.", v => InputFileList = v);
            this.Add("v|verbose", "Include additional output in the log.", v => Verbose = v is not null);
            this.Add("q|quiet", "Do not print any output to the console.", v => Quiet = v is not null);
            this.Add("coe|continue-on-error", "Continue signing multiple files if an error occurs.", v => ContinueOnError = v is not null);
            this.Add("colors", "Enable color output on the command line.", v => Colors = v is not null);
            this.Add("<>", "[files]*");
            Action = Run;
        }

        private HashSet<string> GetAllFiles(string[] additionalFiles)
        {
            var allFiles = new HashSet<string>();
            foreach (string file in additionalFiles)
            {
                if (!string.IsNullOrWhiteSpace(file))
                    allFiles.Add(file);
            }
            if (!string.IsNullOrWhiteSpace(InputFileList))
            {
                foreach (string line in File.ReadLines(InputFileList))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        allFiles.Add(line);
                }
            }
            return allFiles;
        }

        private ValueTask<int> Run(CommandRunContext context, string[] arguments)
        {
            bool valid = ValidateArguments(context);
            HashSet<string>? allFiles = null;

            if (valid)
            {
                allFiles = GetAllFiles(arguments);
                valid = ValidateFiles(context, allFiles);
            }

            if (valid && allFiles is not null)
            {
                return RunSignWith(allFiles);
            }

            context.Error.WriteLine();
            context.Error.WriteLine("Use --help for additional information and usage.");
            return ValueTask.FromResult(E_INVALIDARG);
        }

        private async ValueTask<int> RunSignWith(HashSet<string> allFiles)
        {
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddSimpleConsole(c =>
                {
                    c.IncludeScopes = true;
                    c.ColorBehavior = Colors ? LoggerColorBehavior.Enabled : LoggerColorBehavior.Disabled;
                });
                builder.SetMinimumLevel(Quiet ? LogLevel.Critical : Verbose ? LogLevel.Trace : LogLevel.Information);
            });

            var logger = loggerFactory.CreateLogger<SignWithCommand>();

            var configuration = new AzureKeyVaultSignConfigurationSet
            {
                AzureKeyVaultUrl = new Uri(KeyVaultUrl!),
                AzureKeyVaultCertificateName = KeyVaultCertificate,
                AzureKeyVaultCertificateVersion = KeyVaultCertificateVersion,
                AzureClientId = KeyVaultClientId,
                AzureTenantId = KeyVaultTenantId,
                AzureAccessToken = KeyVaultAccessToken,
                AzureClientSecret = KeyVaultClientSecret,
                ManagedIdentity = UseManagedIdentity,
                AzureAuthority = AzureAuthority,
            };

            TimestampOptions timestampOptions;
            if (Rfc3161TimestampUrl is not null)
            {
                timestampOptions = new TimestampOptions(Rfc3161TimestampUrl, ParseHashAlgorithm(TimestampDigestAlgorithm), TimestampKind.RFC3161);
            }
            else if (AuthenticodeTimestampUrl is not null)
            {
                logger.LogWarning("Authenticode timestamps should only be used for compatibility purposes. RFC3161 timestamps should be used.");
                timestampOptions = new TimestampOptions(AuthenticodeTimestampUrl, default, TimestampKind.Authenticode);
            }
            else
            {
                logger.LogWarning("Signatures will not be timestamped. Signatures will become invalid when the signing certificate expires.");
                timestampOptions = TimestampOptions.None;
            }

            var discoverer = new KeyVaultConfigurationDiscoverer(logger);
            var materializedResult = await discoverer.Materialize(configuration);
            AzureKeyVaultMaterializedConfiguration materialized;

            switch (materializedResult)
            {
                case ErrorOr<AzureKeyVaultMaterializedConfiguration>.Ok ok:
                    materialized = ok.Value;
                    break;
                default:
                    logger.LogError("Failed to get configuration from Azure Key Vault.");
                    return E_INVALIDARG;
            }

            // Built-in engines + any discovered plugins
            var engines = new List<ISigningEngine> { new AuthenticodeSigningEngine() };
            string pluginsDirectory = PluginsDir ?? Path.Combine(AppContext.BaseDirectory, "plugins");
            engines.AddRange(PluginLoader.LoadEnginesFromDirectory(pluginsDirectory));

            logger.LogTrace("Loaded engines: {Engines}", string.Join(", ", engines.ConvertAll(e => e.Name)));

            var clientOptions = new CryptographyClientOptions
            {
                Retry =
                {
                    Delay = TimeSpan.FromSeconds(2),
                    MaxDelay = TimeSpan.FromSeconds(16),
                    MaxRetries = 5,
                    Mode = RetryMode.Exponential,
                },
            };

            var cryptoClient = new CryptographyClient(materialized.KeyId, materialized.TokenCredential, clientOptions);
            using var keyVaultKey = await cryptoClient.CreateRSAAsync();

            var hashAlgorithm = ParseHashAlgorithm(FileDigestAlgorithm);
            int failed = 0, succeeded = 0;
            var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                logger.LogInformation("Cancelling signing operations.");
            };

            foreach (string filePath in allFiles)
            {
                if (cts.IsCancellationRequested)
                {
                    break;
                }

                using (logger.BeginScope("File: {Id}", filePath))
                {
                    logger.LogInformation("Signing file.");

                    ISigningEngine? engine = SelectEngine(engines, filePath, EngineName, logger);
                    if (engine is null)
                    {
                        logger.LogError("No signing engine found for this file type. Use --engine to specify one by name.");
                        failed++;
                        if (!ContinueOnError || allFiles.Count == 1)
                        {
                            break;
                        }
                        continue;
                    }

                    logger.LogTrace("Using engine '{Engine}'.", engine.Name);

                    var request = new SigningRequest(
                        filePath: filePath,
                        key: keyVaultKey,
                        certificate: materialized.PublicCertificate,
                        hashAlgorithm: hashAlgorithm,
                        timestamp: timestampOptions,
                        description: SignDescription,
                        descriptionUrl: SignDescriptionUrl,
                        logger: loggerFactory.CreateLogger(engine.Name));

                    bool ok;
                    try
                    {
                        ok = await engine.SignAsync(request, cts.Token);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Signing engine threw an exception.");
                        ok = false;
                    }

                    if (ok)
                    {
                        logger.LogInformation("Signing completed successfully.");
                        succeeded++;
                    }
                    else
                    {
                        logger.LogError("Signing failed.");
                        failed++;
                        if (!ContinueOnError || allFiles.Count == 1)
                        {
                            break;
                        }
                    }
                }
            }

            logger.LogInformation("Successful operations: {succeeded}", succeeded);
            logger.LogInformation("Failed operations: {failed}", failed);

            if (failed > 0 && succeeded == 0)
            {
                return E_ALL_FAILED;
            }
            else if (failed > 0)
            {
                return S_SOME_SUCCESS;
            }
            else
            {
                return S_OK;
            }
        }

        private static ISigningEngine? SelectEngine(
            IReadOnlyList<ISigningEngine> engines,
            string filePath,
            string? engineName,
            ILogger logger)
        {
            if (engineName is not null)
            {
                foreach (ISigningEngine e in engines)
                {
                    if (e.Name.Equals(engineName, StringComparison.OrdinalIgnoreCase))
                    {
                        return e;
                    }
                }
                logger.LogError("No engine named '{EngineName}' was found. Available engines: {Available}",
                    engineName, GetEngineNames(engines));
                return null;
            }

            string ext = Path.GetExtension(filePath);
            foreach (ISigningEngine e in engines)
            {
                foreach (string supported in e.SupportedExtensions)
                {
                    if (supported.Equals(ext, StringComparison.OrdinalIgnoreCase))
                    {
                        return e;
                    }
                }
            }

            return null;
        }

        private static string GetEngineNames(IReadOnlyList<ISigningEngine> engines)
        {
            var names = new string[engines.Count];
            for (int i = 0; i < engines.Count; i++)
            {
                names[i] = engines[i].Name;
            }
            return string.Join(", ", names);
        }

        private bool ValidateArguments(CommandRunContext context)
        {
            bool valid = true;

            if (KeyVaultUrl is null)
            {
                context.Error.WriteLine("--azure-key-vault-url is required.");
                valid = false;
            }

            if (KeyVaultCertificate is null)
            {
                context.Error.WriteLine("--azure-key-vault-certificate is required.");
                valid = false;
            }

            if (Quiet && Verbose)
            {
                context.Error.WriteLine("Cannot use '--quiet' and '--verbose' options together.");
                valid = false;
            }

            if (!OneTrue(KeyVaultAccessToken is not null, KeyVaultClientId is not null, UseManagedIdentity))
            {
                context.Error.WriteLine("One of '--azure-key-vault-accesstoken', '--azure-key-vault-client-id' or '--azure-key-vault-managed-identity' must be supplied.");
                valid = false;
            }

            if (Rfc3161TimestampUrl is not null && AuthenticodeTimestampUrl is not null)
            {
                context.Error.WriteLine("Cannot use '--timestamp-rfc3161' and '--timestamp-authenticode' options together.");
                valid = false;
            }

            if (KeyVaultClientId is not null && KeyVaultClientSecret is null)
            {
                context.Error.WriteLine("Must supply '--azure-key-vault-client-secret' when using '--azure-key-vault-client-id'.");
                valid = false;
            }

            if (KeyVaultClientId is not null && KeyVaultTenantId is null)
            {
                context.Error.WriteLine("Must supply '--azure-key-vault-tenant-id' when using '--azure-key-vault-client-id'.");
                valid = false;
            }

            if (UseManagedIdentity && (KeyVaultAccessToken is not null || KeyVaultClientId is not null))
            {
                context.Error.WriteLine("Cannot use '--azure-key-vault-managed-identity' and '--azure-key-vault-accesstoken' or '--azure-key-vault-client-id'.");
                valid = false;
            }

            if (InputFileList is not null && !File.Exists(InputFileList))
            {
                context.Error.WriteLine($"File '{InputFileList}' does not exist.");
                valid = false;
            }

            if (AzureAuthority is not null && AuthorityHostNames.GetUriForAzureAuthorityIdentifier(AzureAuthority) is null)
            {
                context.Error.WriteLine($"'{AzureAuthority}' is not a valid value for '--azure-authority'.");
                valid = false;
            }

            return valid;
        }

        private static bool ValidateFiles(CommandRunContext context, HashSet<string> allFiles)
        {
            bool valid = true;

            if (allFiles.Count == 0)
            {
                context.Error.WriteLine("At least one file must be specified to sign.");
                valid = false;
            }
            else
            {
                foreach (string file in allFiles)
                {
                    if (!File.Exists(file))
                    {
                        context.Error.WriteLine($"File '{file}' does not exist.");
                        valid = false;
                    }
                }
            }

            return valid;
        }

        private static HashAlgorithmName ParseHashAlgorithm(string? hashAlgorithm) =>
            hashAlgorithm?.ToUpperInvariant() switch
            {
                "SHA1" => HashAlgorithmName.SHA1,
                "SHA256" => HashAlgorithmName.SHA256,
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256,
            };

        private static bool OneTrue(params bool[] values)
        {
            int count = 0;
            for (int i = 0; i < values.Length && count < 2; i++)
            {
                if (values[i]) count++;
            }
            return count == 1;
        }
    }
}
