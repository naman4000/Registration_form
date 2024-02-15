function validateAndRegister() {
    var username = document.getElementById('username').value;
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;
    var confirmPassword = document.getElementById('confirmPassword').value;

    // Simple client-side validation
    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return;
    }

    // Hash the password using bcrypt.js (client-side hashing for example purposes)
    var saltRounds = 10;
    bcrypt.hash(password, saltRounds, function(err, hash) {
        if (err) {
            alert('Error hashing password');
        } else {
            // Displaying the hashed password for demonstration purposes
            alert('Username: ' + username + '\nEmail: ' + email + '\nHashed Password: ' + hash);
            // In a real scenario, send the hashed password and other details to the server for storage.
        }
    });
}