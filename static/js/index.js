document.querySelector('.confirm-button').addEventListener('click', function() {
    const input = document.querySelector('.id-input').value;

    if (input) {
        fetch('/check-user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: input })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                window.location.href = `/vote-pres?id=${encodeURIComponent(input)}`;
            } else {
                alert(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while checking the user ID.');
        });
    } else {
        alert('Please enter an ID.');
    }
});

document.querySelector('.cancel-button').addEventListener('click', function() {
    document.querySelector('.id-input').value = '';
});




