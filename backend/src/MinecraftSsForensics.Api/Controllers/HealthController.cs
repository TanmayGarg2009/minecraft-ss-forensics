using Microsoft.AspNetCore.Mvc;
using MinecraftSsForensics.Api.Data;

namespace MinecraftSsForensics.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class HealthController : ControllerBase
{
    private readonly ForensicsDbContext _dbContext;
    private static readonly DateTimeOffset StartTime = DateTimeOffset.UtcNow;

    public HealthController(ForensicsDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [HttpGet]
    public async Task<IActionResult> GetHealth(CancellationToken cancellationToken)
    {
        bool dbHealthy;
        try
        {
            dbHealthy = await _dbContext.Database.CanConnectAsync(cancellationToken);
        }
        catch
        {
            dbHealthy = false;
        }

        var status = dbHealthy ? "Healthy" : "Degraded";
        var result = new
        {
            Status = status,
            Timestamp = DateTimeOffset.UtcNow,
            Uptime = DateTimeOffset.UtcNow - StartTime,
            Database = dbHealthy ? "Connected" : "Disconnected",
            Version = "1.0.0",
            Service = "Minecraft SS Forensics Ingestion & Viewer API"
        };

        return dbHealthy ? Ok(result) : StatusCode(503, result);
    }
}
