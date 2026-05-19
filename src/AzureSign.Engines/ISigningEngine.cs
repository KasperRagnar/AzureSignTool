using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AzureSign.Engines
{
    public interface ISigningEngine
    {
        string Name { get; }
        string Description { get; }
        IReadOnlyList<string> SupportedExtensions { get; }
        Task<bool> SignAsync(SigningRequest request, CancellationToken cancellationToken = default);
    }
}
