document.addEventListener('DOMContentLoaded', function () {
    // Select all position groups
    const positionGroups = document.querySelectorAll('.position-group');
    let currentIndex = 0; // Track the current active group index
    const selections = {}; // Store user selections
    const displayId = document.getElementById('display-id'); // Element to display user ID
    const reviewSection = document.getElementById('review-section'); // Section to review selections
    const selectionList = document.getElementById('selection-list'); // List to display selections

    // Function to get a query parameter from the URL
    function getQueryParam(param) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param);
    }

    // Fetch user ID from URL parameter and display it
    const userId = getQueryParam('id') || 'Unknown'; // Default to 'Unknown' if not found
    displayId.textContent = userId;

    // Save the current selection for the active group
    function saveSelection() {
        const activeGroup = positionGroups[currentIndex];
        const position = activeGroup.dataset.position; // Get the position (e.g., president)
        const selectedCandidate = activeGroup.querySelector('input[type="radio"]:checked');
        if (selectedCandidate) {
            selections[position] = selectedCandidate.value; // Save the selected candidate
        }
    }

    // Navigate to the next position group
    function navigateToNext() {
        if (currentIndex < positionGroups.length - 1) {
            saveSelection(); // Save current selection before moving
            positionGroups[currentIndex].classList.remove('active'); // Hide current group
            currentIndex++; // Move to the next group
            positionGroups[currentIndex].classList.add('active'); // Show next group
        }
    }

    // Navigate to the previous position group
    function navigateToPrevious() {
        if (currentIndex > 0) {
            saveSelection(); // Save current selection before moving
            positionGroups[currentIndex].classList.remove('active'); // Hide current group
            currentIndex--; // Move to the previous group
            positionGroups[currentIndex].classList.add('active'); // Show previous group
        }
    }

    // Review the selections made by the user
    function reviewSelections() {
        saveSelection(); // Save the last selection
        selectionList.innerHTML = `<li>User ID: ${userId}</li>`; // Display user ID
        for (const [position, candidate] of Object.entries(selections)) {
            const listItem = document.createElement('li');
            listItem.textContent = `${position}: ${candidate}`; // Display each selection
            selectionList.appendChild(listItem);
        }
        reviewSection.style.display = 'block'; // Show the review section
    }

    // Submit the votes to the server
    function submitVotes() {
        fetch('/submit-votes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId, selections }) // Send user ID and selections
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Votes submitted successfully!');
                // Redirect to index.html (home page)
                window.location.href = '/';
            } else {
                alert(data.message || 'Something went wrong.');
            }
        })
        .catch(error => {
            console.error('Error submitting votes:', error);
            alert('Failed to submit votes. Please try again.');
        });
    }

    // Cancel the review process
    function cancelReview() {
        reviewSection.style.display = 'none'; // Hide the review section
    }

    // Add event listeners for navigation and review buttons
    document.getElementById('next-button').addEventListener('click', navigateToNext);
    document.getElementById('prev-button').addEventListener('click', navigateToPrevious);
    document.getElementById('review-button').addEventListener('click', reviewSelections);
    document.getElementById('submit-button').addEventListener('click', submitVotes);
    document.getElementById('cancel-button').addEventListener('click', cancelReview);

    // Initialize the first group as active
    if (positionGroups.length > 0) {
        positionGroups[0].classList.add('active');
    }
});
