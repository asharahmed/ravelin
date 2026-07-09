using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ravelin.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAcceptedRiskExpiry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "AcceptedRiskUntil",
                table: "Findings",
                type: "datetimeoffset",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AcceptedRiskUntil",
                table: "Findings");
        }
    }
}
