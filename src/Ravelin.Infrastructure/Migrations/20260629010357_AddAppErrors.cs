using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ravelin.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAppErrors : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AppErrors",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Fingerprint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ExceptionType = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Message = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: true),
                    StackExcerpt = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    RequestMethod = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    RequestPath = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    LastCorrelationId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Occurrences = table.Column<int>(type: "int", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    IssueIdentifier = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    IssueUrl = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    IssueSyncedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppErrors", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AppErrors_Fingerprint",
                table: "AppErrors",
                column: "Fingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AppErrors_Status_LastSeenAt",
                table: "AppErrors",
                columns: new[] { "Status", "LastSeenAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AppErrors");
        }
    }
}
