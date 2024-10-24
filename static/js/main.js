document.addEventListener('DOMContentLoaded', function() {
    // File upload validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.files[0].size > 500 * 1024 * 1024) {
                alert('File size exceeds 500MB limit');
                this.value = '';
            }
        });
    });
});
