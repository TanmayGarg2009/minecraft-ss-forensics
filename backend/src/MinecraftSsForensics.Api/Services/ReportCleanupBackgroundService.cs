namespace MinecraftSsForensics.Api.Services;

public class ReportCleanupBackgroundService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<ReportCleanupBackgroundService> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromHours(1);

    public ReportCleanupBackgroundService(IServiceProvider serviceProvider, ILogger<ReportCleanupBackgroundService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Report cleanup background service started. Interval: {Interval}", _checkInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var reportService = scope.ServiceProvider.GetRequiredService<IReportService>();
                var purged = await reportService.CleanupExpiredReportsAsync(stoppingToken);
                if (purged > 0)
                {
                    _logger.LogInformation("Purged {Count} expired reports during scheduled maintenance", purged);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during scheduled report expiration cleanup");
            }

            try
            {
                await Task.Delay(_checkInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
