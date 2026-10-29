using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Api.Models.Dtos.Presentation;

namespace MinecraftSsForensics.Api.Services;

public interface IReportService
{
    Task<SubmitReportResponse> SubmitReportAsync(SubmitReportRequest request, string baseUrl, CancellationToken cancellationToken = default);
    Task<ReportDetailResponse?> GetReportByPublicIdAsync(string publicId, CancellationToken cancellationToken = default);
    Task<EvidenceDetailDto?> GetEvidenceItemAsync(string publicId, string evidenceId, CancellationToken cancellationToken = default);
    Task<bool> DeleteReportAsync(string publicId, string deletionKey, CancellationToken cancellationToken = default);
    Task<int> CleanupExpiredReportsAsync(CancellationToken cancellationToken = default);
}
