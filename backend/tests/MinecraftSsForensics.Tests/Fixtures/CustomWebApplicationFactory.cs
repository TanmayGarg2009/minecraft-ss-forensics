using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MinecraftSsForensics.Api.Data;
using MinecraftSsForensics.Api.Services;

namespace MinecraftSsForensics.Tests.Fixtures;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = "TestForensicsDb_" + Guid.NewGuid().ToString("N");
    private readonly string _testStorageDir = Path.Combine(Path.GetTempPath(), "MinecraftSsForensics_TestStorage_" + Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            // Replace DB with isolated InMemoryDatabase
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ForensicsDbContext>));
            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            services.AddDbContext<ForensicsDbContext>(options =>
            {
                options.UseInMemoryDatabase(_databaseName);
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (Directory.Exists(_testStorageDir))
        {
            try
            {
                Directory.Delete(_testStorageDir, true);
            }
            catch
            {
                // Ignored on cleanup
            }
        }
    }
}
