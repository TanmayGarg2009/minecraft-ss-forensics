using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using MinecraftSsForensics.Api.Data;
using MinecraftSsForensics.Api.Middleware;
using MinecraftSsForensics.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Add Controllers & JSON options
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
    });

// API Documentation / Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Minecraft SS Forensics Ingestion & Reporting API",
        Version = "v1",
        Description = "Consent-based Minecraft Screenshare Forensic Investigation Platform — Stage 1 Ingestion and Public Bearer-Report Viewer API."
    });
});

// Database configuration: PostgreSQL with Sqlite local development fallback
var dbProvider = builder.Configuration["Database:Provider"] ?? "Sqlite";
if (dbProvider.Equals("PostgreSql", StringComparison.OrdinalIgnoreCase))
{
    var postgresConn = builder.Configuration.GetConnectionString("PostgreSql") 
                       ?? builder.Configuration["Database:PostgreSqlConnectionString"];
    builder.Services.AddDbContext<ForensicsDbContext>(options =>
        options.UseNpgsql(postgresConn));
}
else
{
    var appData = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
    if (!Directory.Exists(appData))
    {
        Directory.CreateDirectory(appData);
    }
    var sqliteConn = builder.Configuration.GetConnectionString("Sqlite") 
                     ?? builder.Configuration["Database:SqliteConnectionString"] 
                     ?? $"Data Source={Path.Combine(appData, "forensics.db")}";
    builder.Services.AddDbContext<ForensicsDbContext>(options =>
        options.UseSqlite(sqliteConn));
}

// Custom domain services
builder.Services.AddSingleton<IIdentifierGenerator, SecureIdentifierGenerator>();
builder.Services.AddSingleton<IStorageService, LocalEvidenceStorageService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddHostedService<ReportCleanupBackgroundService>();

// CORS configuration for frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("FrontendCorsPolicy", policy =>
    {
        policy.SetIsOriginAllowed(_ => true)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .WithExposedHeaders("Cache-Control", "Location");
    });
});

// Rate Limiting
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("ReportsSubmissionPolicy", limiterOptions =>
    {
        limiterOptions.PermitLimit = 30;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 5;
    });
});

var app = builder.Build();

// Ensure database schema is created
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ForensicsDbContext>();
    db.Database.EnsureCreated();
}

// Exception handling middleware
app.UseMiddleware<ExceptionHandlingMiddleware>();

// Security Headers middleware
app.UseMiddleware<SecurityHeadersMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Minecraft SS Forensics API v1");
        c.RoutePrefix = "swagger";
    });
}

app.UseCors("FrontendCorsPolicy");

app.UseRateLimiter();

app.UseAuthorization();

app.MapControllers();

app.Run();

// For WebApplicationFactory in integration tests
public partial class Program { }
