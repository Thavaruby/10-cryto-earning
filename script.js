async function uploadAndConvertPDF(file, selectedFormat) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('format', selectedFormat);

    try {
        // Render.com / Railway backend API URL-ai inge kodukkavum
        const response = await fetch('https://your-backend-url.onrender.com/convert', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Conversion failed');

        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `converted_file.${selectedFormat}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        
        alert('File Converted Successfully!');
    } catch (err) {
        console.error(err);
        alert('Error during conversion.');
    }
}
