namespace MinecraftSsForensics.Api.Services;

public interface IStorageService
{
    Task<string> SaveEvidencePayloadAsync(string publicId, string evidenceId, string payloadContent, CancellationToken cancellationToken = default);
    Task<string?> GetEvidencePayloadAsync(string publicId, string evidenceId, CancellationToken cancellationToken = default);
    Task DeleteReportEvidenceAsync(string publicId, CancellationToken cancellationToken = default);
}
