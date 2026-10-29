using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MinecraftSsForensics.Api.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Reports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    PublicId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    DeletionKeyHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    SchemaVersion = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    ScannerVersion = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UploadedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ScanStartedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    ScanCompletedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    ScanMode = table.Column<string>(type: "TEXT", nullable: false),
                    OsName = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    OsVersion = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    OsArchitecture = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    DetectedMinecraftVersionsJson = table.Column<string>(type: "TEXT", nullable: false),
                    DetectedLoadersJson = table.Column<string>(type: "TEXT", nullable: false),
                    ConsentGiven = table.Column<bool>(type: "INTEGER", nullable: false),
                    CollectionScopeVersion = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ConsentTimestamp = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ProcessingStatus = table.Column<string>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    TotalChecks = table.Column<int>(type: "INTEGER", nullable: false),
                    PassedChecks = table.Column<int>(type: "INTEGER", nullable: false),
                    FlaggedChecks = table.Column<int>(type: "INTEGER", nullable: false),
                    UnavailableChecks = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Reports", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DiagnosticItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ReportId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CheckName = table.Column<string>(type: "TEXT", maxLength: 150, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false),
                    Recommendation = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiagnosticItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DiagnosticItems_Reports_ReportId",
                        column: x => x.ReportId,
                        principalTable: "Reports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EvidenceItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ReportId = table.Column<Guid>(type: "TEXT", nullable: false),
                    PublicEvidenceId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Type = table.Column<string>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    RawContent = table.Column<string>(type: "TEXT", nullable: true),
                    StructuredPayloadJson = table.Column<string>(type: "TEXT", nullable: true),
                    Sha256Hash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    IsAvailable = table.Column<bool>(type: "INTEGER", nullable: false),
                    DiagnosticMessage = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    CapturedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EvidenceItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EvidenceItems_Reports_ReportId",
                        column: x => x.ReportId,
                        principalTable: "Reports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Findings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ReportId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RuleId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Category = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<string>(type: "TEXT", nullable: false),
                    Confidence = table.Column<string>(type: "TEXT", nullable: false),
                    Explanation = table.Column<string>(type: "TEXT", nullable: false),
                    ObservedEvidenceJson = table.Column<string>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    FileSizeBytes = table.Column<long>(type: "INTEGER", nullable: true),
                    FileSha256 = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    FileCreatedTime = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    FileModifiedTime = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    FileLastAccessTime = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: true),
                    ProcessName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    ProcessCommandLine = table.Column<string>(type: "TEXT", nullable: true),
                    FirstObservedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    LastObservedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    EvidenceSource = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionRuleVersion = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    LimitationsAndFalsePositives = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Findings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Findings_Reports_ReportId",
                        column: x => x.ReportId,
                        principalTable: "Reports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TimelineEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ReportId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Timestamp = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    IsInferred = table.Column<bool>(type: "INTEGER", nullable: false),
                    Category = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Confidence = table.Column<string>(type: "TEXT", nullable: false),
                    CorrelationGroup = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimelineEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TimelineEvents_Reports_ReportId",
                        column: x => x.ReportId,
                        principalTable: "Reports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DiagnosticItems_ReportId",
                table: "DiagnosticItems",
                column: "ReportId");

            migrationBuilder.CreateIndex(
                name: "IX_EvidenceItems_ReportId_PublicEvidenceId",
                table: "EvidenceItems",
                columns: new[] { "ReportId", "PublicEvidenceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Findings_ReportId_RuleId",
                table: "Findings",
                columns: new[] { "ReportId", "RuleId" });

            migrationBuilder.CreateIndex(
                name: "IX_Reports_CreatedAt",
                table: "Reports",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Reports_ExpiresAt",
                table: "Reports",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_Reports_PublicId",
                table: "Reports",
                column: "PublicId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TimelineEvents_ReportId_Timestamp",
                table: "TimelineEvents",
                columns: new[] { "ReportId", "Timestamp" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DiagnosticItems");

            migrationBuilder.DropTable(
                name: "EvidenceItems");

            migrationBuilder.DropTable(
                name: "Findings");

            migrationBuilder.DropTable(
                name: "TimelineEvents");

            migrationBuilder.DropTable(
                name: "Reports");
        }
    }
}
