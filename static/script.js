// // JavaScript for live search functionality
// document.addEventListener("DOMContentLoaded", () => {
//     const searchInput = document.querySelector("#search");
//     const plantList = document.querySelector("#plant-list");

//     searchInput.addEventListener("input", () => {
//         const query = searchInput.value.toLowerCase();
//         const plants = plantList.querySelectorAll("li");

//         plants.forEach(plant => {
//             const plantName = plant.textContent.toLowerCase();
//             if (plantName.includes(query)) {
//                 plant.style.display = "block";
//             } else {
//                 plant.style.display = "none";
//             }
//         });
//     });
// });
