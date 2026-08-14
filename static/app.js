function searchFiles() {

    const input = document.getElementById("fileSearch");

    if (!input) {
        return;
    }

    const search = input.value.toLowerCase().trim();

    const cards = document.querySelectorAll(".file-card");

    cards.forEach(function(card) {

        const nameElement =
            card.querySelector(".file-name");

        if (!nameElement) {
            return;
        }

        const fileName =
            nameElement.textContent.toLowerCase();

        card.style.display =
            fileName.includes(search)
                ? "flex"
                : "none";
    });
}