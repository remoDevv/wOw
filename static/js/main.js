document.addEventListener('DOMContentLoaded', function() {
    // File size validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.files[0] && this.files[0].size > 500 * 1024 * 1024) {
                alert('File size exceeds 500MB limit');
                this.value = '';
            }
        });
    });

    // Password toggle functionality
    const togglePassword = document.querySelector('#togglePassword');
    const password = document.querySelector('#p12_password');
    
    if (togglePassword && password) {
        togglePassword.addEventListener('click', function(e) {
            e.preventDefault();
            const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
            password.setAttribute('type', type);
            this.querySelector('i').classList.toggle('bi-eye');
            this.querySelector('i').classList.toggle('bi-eye-slash');
        });
    }
});
