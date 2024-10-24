document.addEventListener('DOMContentLoaded', function() {
    const iconSizes = {
        'icon': 1024 * 1024,        // 1MB for small icon
        'full_size_icon': 2 * 1024 * 1024  // 2MB for large icon
    };
    
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.name === 'icon' || this.name === 'full_size_icon') {
                if (this.files[0] && this.files[0].size > iconSizes[this.name]) {
                    alert(`Icon file size exceeds limit (${this.name === 'icon' ? '1MB' : '2MB'})`);
                    this.value = '';
                }
            } else if (this.files[0] && this.files[0].size > 500 * 1024 * 1024) {
                alert('File size exceeds 500MB limit');
                this.value = '';
            }
        });
    });
});
