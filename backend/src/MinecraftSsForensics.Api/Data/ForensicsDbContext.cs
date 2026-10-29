using Microsoft.EntityFrameworkCore;
using MinecraftSsForensics.Api.Models.Domain;

namespace MinecraftSsForensics.Api.Data;

public class ForensicsDbContext : DbContext
{
    public ForensicsDbContext(DbContextOptions<ForensicsDbContext> options) : base(options)
    {
    }

    public DbSet<Report> Reports => Set<Report>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<EvidenceItem> EvidenceItems => Set<EvidenceItem>();
    public DbSet<TimelineEvent> TimelineEvents => Set<TimelineEvent>();
    public DbSet<DiagnosticItem> DiagnosticItems => Set<DiagnosticItem>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Report
        modelBuilder.Entity<Report>(entity =>
        {
            entity.HasIndex(r => r.PublicId).IsUnique();
            entity.HasIndex(r => r.ExpiresAt);
            entity.HasIndex(r => r.CreatedAt);

            entity.Property(r => r.ScanMode).HasConversion<string>();
            entity.Property(r => r.ProcessingStatus).HasConversion<string>();

            entity.HasMany(r => r.Findings)
                  .WithOne(f => f.Report)
                  .HasForeignKey(f => f.ReportId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(r => r.EvidenceItems)
                  .WithOne(e => e.Report)
                  .HasForeignKey(e => e.ReportId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(r => r.TimelineEvents)
                  .WithOne(t => t.Report)
                  .HasForeignKey(t => t.ReportId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(r => r.DiagnosticItems)
                  .WithOne(d => d.Report)
                  .HasForeignKey(d => d.ReportId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Finding
        modelBuilder.Entity<Finding>(entity =>
        {
            entity.HasIndex(f => new { f.ReportId, f.RuleId });
            entity.Property(f => f.Category).HasConversion<string>();
            entity.Property(f => f.Severity).HasConversion<string>();
            entity.Property(f => f.Confidence).HasConversion<string>();
            entity.Property(f => f.EvidenceSource).HasConversion<string>();
        });

        // EvidenceItem
        modelBuilder.Entity<EvidenceItem>(entity =>
        {
            entity.HasIndex(e => new { e.ReportId, e.PublicEvidenceId }).IsUnique();
            entity.Property(e => e.Type).HasConversion<string>();
        });

        // TimelineEvent
        modelBuilder.Entity<TimelineEvent>(entity =>
        {
            entity.HasIndex(t => new { t.ReportId, t.Timestamp });
            entity.Property(t => t.Confidence).HasConversion<string>();
        });
    }
}
