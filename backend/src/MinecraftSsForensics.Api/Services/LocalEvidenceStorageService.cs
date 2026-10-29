namespace MinecraftSsForensics.Api.Services;

public class LocalEvidenceStorageService : IStorageService
{
    private readonly string _storageDirectory;
    private readonly ILogger<LocalEvidenceStorageService> _logger;

    public LocalEvidenceStorageService(IConfiguration configuration, IWebHostEnvironment environment, ILogger<LocalEvidenceStorageService> logger)
    {
        _logger = logger;
        var configuredPath = configuration["Storage:EvidenceDirectory"];
        _storageDirectory = !string.IsNullOrWhiteSpace(configuredPath)
            ? Path.GetFullPath(configuredPath)
            : Path.Combine(environment.ContentRootPath, "App_Data", "evidence_storage");

        if (!Directory.Exists(_storageDirectory))
        {
            Directory.CreateDirectory(_storageDirectory);
        }
    }

    public async Task<string> SaveEvidencePayloadAsync(string publicId, string evidenceId, string payloadContent, CancellationToken cancellationToken = default)
    {
        var targetFile = GetSafeFilePath(publicId, evidenceId);
        var dir = Path.GetDirectoryName(targetFile)!;
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        await File.WriteAllTextAsync(targetFile, payloadContent, cancellationToken);
        return targetFile;
    }

    public async Task<string?> GetEvidencePayloadAsync(string publicId, string evidenceId, CancellationToken cancellationToken = default)
    {
        var targetFile = GetSafeFilePath(publicId, evidenceId);
        if (!File.Exists(targetFile))
        {
            return null;
        }

        return await File.ReadAllTextAsync(targetFile, cancellationToken);
    }

    public Task DeleteReportEvidenceAsync(string publicId, CancellationToken cancellationToken = default)
    {
        var safeReportFolder = Path.Combine(_storageDirectory, SanitizeName(publicId));
        var fullPath = Path.GetFullPath(safeReportFolder);

        if (!fullPath.StartsWith(_storageDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Invalid storage path traversal attempt.");
        }

        if (Directory.Exists(fullPath))
        {
            Directory.Delete(fullPath, recursive: true);
            _logger.LogInformation("Deleted evidence directory for report {PublicId}", publicId);
        }

        return Task.CompletedTask;
    }

    private string GetSafeFilePath(string publicId, string evidenceId)
    {
        var safePublicId = SanitizeName(publicId);
        var safeEvidenceId = SanitizeName(evidenceId) + ".dat";

        var combinedPath = Path.GetFullPath(Path.Combine(_storageDirectory, safePublicId, safeEvidenceId));

        if (!combinedPath.StartsWith(_storageDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Storage path traversal attempted.");
        }

        return combinedPath;
    }

    private static string SanitizeName(string input)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return new string(input.Where(c => !invalid.Contains(c) && c != '/' && c != '\\').ToArray());
    }
}
