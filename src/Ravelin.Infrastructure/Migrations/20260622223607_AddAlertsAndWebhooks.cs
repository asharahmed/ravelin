using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ravelin.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAlertsAndWebhooks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "WebhookUrl",
                table: "Projects",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "FindingAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    FindingId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    State = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    RaisedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    AcknowledgedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    AcknowledgedBy = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    NotifiedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FindingAlerts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_FindingAlerts_Findings_FindingId",
                        column: x => x.FindingId,
                        principalTable: "Findings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FindingAlerts_AcknowledgedAt",
                table: "FindingAlerts",
                column: "AcknowledgedAt");

            migrationBuilder.CreateIndex(
                name: "IX_FindingAlerts_FindingId_State",
                table: "FindingAlerts",
                columns: new[] { "FindingId", "State" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_FindingAlerts_ProjectId_RaisedAt",
                table: "FindingAlerts",
                columns: new[] { "ProjectId", "RaisedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FindingAlerts");

            migrationBuilder.DropColumn(
                name: "WebhookUrl",
                table: "Projects");
        }
    }
}
