using Microsoft.EntityFrameworkCore.Migrations;

namespace MVC_proj.Migrations
{
    public partial class addingSliderIDColumn : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "SliderId",
                table: "SliderImages",
                type: "int",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_SliderImages_SliderId",
                table: "SliderImages",
                column: "SliderId");

            migrationBuilder.AddForeignKey(
                name: "FK_SliderImages_Sliders_SliderId",
                table: "SliderImages",
                column: "SliderId",
                principalTable: "Sliders",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_SliderImages_Sliders_SliderId",
                table: "SliderImages");

            migrationBuilder.DropIndex(
                name: "IX_SliderImages_SliderId",
                table: "SliderImages");

            migrationBuilder.DropColumn(
                name: "SliderId",
                table: "SliderImages");
        }
    }
}
