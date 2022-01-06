
$(document).on("keyup", "#search__input", function () {

         let searchedCategory = $(this).val();

         $.ajax({
             type: "GET",
             url: "Category/Search?searchedCategory=" + searchedCategory,
             success: function (res) {
                  $("#search-container li:not(:first-child)").remove();
                 $("#search-container").append(res);
             }
         })
    })