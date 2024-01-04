using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace user.Management.API.Migrations
{
    public partial class RolesSeeded : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "122df0b7-1de4-4960-b4b7-609e256ee84b", "1", "Admin", "Admin" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "3fc7ff91-2414-42da-a18b-5f08593a7ef9", "2", "HR", "Human Resources" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "d8f60451-002d-487a-8c6a-ab264e1ddeaf", "2", "User", "User" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "122df0b7-1de4-4960-b4b7-609e256ee84b");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3fc7ff91-2414-42da-a18b-5f08593a7ef9");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "d8f60451-002d-487a-8c6a-ab264e1ddeaf");
        }
    }
}
