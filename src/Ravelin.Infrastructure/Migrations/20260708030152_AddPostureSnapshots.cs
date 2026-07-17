using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ravelin.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddPostureSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PostureSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SnapshotDate = table.Column<DateOnly>(type: "date", nullable: false),
                    TakenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ProjectCount = table.Column<int>(type: "int", nullable: false),
                    TotalOpen = table.Column<int>(type: "int", nullable: false),
                    Breached = table.Column<int>(type: "int", nullable: false),
                    DueSoon = table.Column<int>(type: "int", nullable: false),
                    OnTrack = table.Column<int>(type: "int", nullable: false),
                    CompliancePercent = table.Column<double>(type: "float", nullable: false),
                    ActivelyExploited = table.Column<int>(type: "int", nullable: false),
                    Critical = table.Column<int>(type: "int", nullable: false),
                    High = table.Column<int>(type: "int", nullable: false),
                    Medium = table.Column<int>(type: "int", nullable: false),
                    Low = table.Column<int>(type: "int", nullable: false),
                    Unknown = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PostureSnapshots", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PostureSnapshots_SnapshotDate",
                table: "PostureSnapshots",
                column: "SnapshotDate",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PostureSnapshots");
        }
    }
}
