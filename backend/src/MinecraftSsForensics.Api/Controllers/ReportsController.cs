using Microsoft.AspNetCore.Mvc;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Api.Models.Dtos.Presentation;
using MinecraftSsForensics.Api.Services;
using MinecraftSsForensics.Api.Validation;

namespace MinecraftSsForensics.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class ReportsController : ControllerBase
{
    private readonly IReportService _reportService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ReportsController> _logger;

    public ReportsController(IReportService reportService, IConfiguration configuration, ILogger<ReportsController> logger)
    {
        _reportService = reportService;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Ingest a structured forensic report submitted by the scanner.
    /// </summary>
    [HttpPost]
    [RequestSizeLimit(15 * 1024 * 1024)] // 15 MB payload limit
    public async Task<IActionResult> SubmitReport([FromBody] SubmitReportRequest request, CancellationToken cancellationToken)
    {
        var validator = new ReportSubmissionValidator();
        var validationResult = await validator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            var errors = validationResult.Errors.Select(e => new { Field = e.PropertyName, Error = e.ErrorMessage });
            return BadRequest(new { Message = "Report submission validation failed.", Errors = errors });
        }

        // Determine public frontend base URL to construct the viewer share link
        string frontendBaseUrl;
        if (Request.Headers.TryGetValue("X-Frontend-Base-Url", out var headerUrl) && !string.IsNullOrWhiteSpace(headerUrl))
        {
            frontendBaseUrl = headerUrl.ToString();
        }
        else
        {
            var configured = _configuration["Frontend:PublicBaseUrl"];
            if (!string.IsNullOrWhiteSpace(configured))
            {
                frontendBaseUrl = configured;
            }
            else
            {
                // In local development, frontend runs on port 3000 while API runs on port 5000
                frontendBaseUrl = (Request.Host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || Request.Host.Host.Equals("127.0.0.1"))
                    ? "http://localhost:3000"
                    : $"{Request.Scheme}://{Request.Host}";
            }
        }

        var result = await _reportService.SubmitReportAsync(request, frontendBaseUrl, cancellationToken);

        return CreatedAtAction(nameof(GetReport), new { publicId = result.PublicId }, result);
    }

    /// <summary>
    /// Retrieve a public report using its unguessable public identifier.
    /// </summary>
    [HttpGet("{publicId}")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> GetReport([FromRoute] string publicId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(publicId) || publicId.Length > 64)
        {
            return BadRequest(new { Message = "Invalid report identifier format." });
        }

        var report = await _reportService.GetReportByPublicIdAsync(publicId, cancellationToken);
        if (report == null)
        {
            return NotFound(new { Message = "Report not found or has expired." });
        }

        Response.Headers.Append("Cache-Control", "no-store, no-cache, must-revalidate");
        Response.Headers.Append("Pragma", "no-cache");

        return Ok(report);
    }

    /// <summary>
    /// Retrieve a specific evidence item from a report.
    /// </summary>
    [HttpGet("{publicId}/evidence/{evidenceId}")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> GetEvidence([FromRoute] string publicId, [FromRoute] string evidenceId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(publicId) || string.IsNullOrWhiteSpace(evidenceId))
        {
            return BadRequest(new { Message = "Invalid identifiers." });
        }

        var evidence = await _reportService.GetEvidenceItemAsync(publicId, evidenceId, cancellationToken);
        if (evidence == null)
        {
            return NotFound(new { Message = "Evidence item not found or report expired." });
        }

        return Ok(evidence);
    }

    /// <summary>
    /// Delete a report using the secret deletion key provided during submission.
    /// </summary>
    [HttpDelete("{publicId}")]
    public async Task<IActionResult> DeleteReport(
        [FromRoute] string publicId,
        [FromBody] DeleteReportRequest? body,
        [FromHeader(Name = "X-Deletion-Key")] string? headerKey,
        CancellationToken cancellationToken)
    {
        var key = !string.IsNullOrWhiteSpace(headerKey) ? headerKey : body?.DeletionKey;

        if (string.IsNullOrWhiteSpace(key))
        {
            return BadRequest(new { Message = "Deletion key must be provided in request body or X-Deletion-Key header." });
        }

        var report = await _reportService.GetReportByPublicIdAsync(publicId, cancellationToken);
        if (report == null)
        {
            return NotFound(new { Message = "Report not found or already deleted." });
        }

        var deleted = await _reportService.DeleteReportAsync(publicId, key, cancellationToken);
        if (!deleted)
        {
            return Unauthorized(new { Message = "Invalid deletion key. Deletion denied." });
        }

        return Ok(new DeleteReportResponse
        {
            Success = true,
            Message = $"Report {publicId} and all associated forensic evidence have been permanently deleted."
        });
    }

    /// <summary>
    /// Operational maintenance endpoint to purge expired reports.
    /// </summary>
    [HttpPost("cleanup")]
    public async Task<IActionResult> TriggerCleanup(CancellationToken cancellationToken)
    {
        var cleaned = await _reportService.CleanupExpiredReportsAsync(cancellationToken);
        return Ok(new { Message = $"Cleanup completed. Removed {cleaned} expired report(s)." });
    }
}
