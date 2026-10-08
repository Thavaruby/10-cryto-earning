const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { createWorker } = require('tesseract.js');
const pdfParse = require('pdf-parse');
const docx = require('docx');
const ExcelJS = require('exceljs');
const PptxGenJS = require('pptxgenjs');

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for frontend requests (Cloudflare Pages compatible)
app.use(cors());
app.use(express.json());

// Configure Multer for PDF file uploads
const upload = multer({ dest: 'uploads/' });

// Ensure uploads folder exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

/**
 * Extract text from PDF (Supports Native Text + OCR Fallback for Scanned PDFs)
 */
async function extractContentFromPDF(filePath) {
    const dataBuffer = fs.readFileSync(filePath);
    let extractedText = '';

    try {
        const pdfData = await pdfParse(dataBuffer);
        
        // If readable text exists in PDF
        if (pdfData.text && pdfData.text.trim().length > 30) {
            extractedText = pdfData.text;
        } else {
            // Fallback to OCR using Tesseract.js (Supports English + Tamil)
            const worker = await createWorker('eng+tam');
            const { data: { text } } = await worker.recognize(filePath);
            extractedText = text;
            await worker.terminate();
        }
    } catch (err) {
        // Fallback OCR if pdf-parse fails
        const worker = await createWorker('eng+tam');
        const { data: { text } } = await worker.recognize(filePath);
        extractedText = text;
        await worker.terminate();
    }

    return extractedText;
}

/**
 * Generate Word Buffer (.docx)
 */
async function generateWord(text) {
    const paragraphs = text.split('\n').map(line => {
        return new docx.Paragraph({
            children: [new docx.TextRun({ text: line, size: 24 })]
        });
    });

    const doc = new docx.Document({
        sections: [{ children: paragraphs }]
    });

    return await docx.Packer.toBuffer(doc);
}

/**
 * Generate Excel Buffer (.xlsx)
 */
async function generateExcel(text) {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Extracted Content');

    const lines = text.split('\n');
    lines.forEach((line) => {
        if (line.trim()) {
            // Split by tab, multiple spaces, or commas for table layout
            const cells = line.split(/\t| {3,}|,/);
            worksheet.addRow(cells);
        }
    });

    return await workbook.xlsx.writeBuffer();
}

/**
 * Generate PPT Buffer (.pptx)
 */
async function generatePPT(text) {
    const pptx = new PptxGenJS();
    const lines = text.split('\n').filter(l => l.trim().length > 0);

    // Group lines into slides (approx 10 lines per slide)
    const chunkSize = 10;
    for (let i = 0; i < lines.length; i += chunkSize) {
        const slideText = lines.slice(i, i + chunkSize).join('\n');
        const slide = pptx.addSlide();
        
        slide.addText(slideText, {
            x: 0.5,
            y: 0.5,
            w: '90%',
            h: '85%',
            fontSize: 14,
            color: '363636',
            align: 'left'
        });
    }

    return await pptx.write('nodebuffer');
}

/**
 * Main Conversion Endpoint
 */
app.post('/convert', upload.single('file'), async (req, res) => {
    const file = req.file;
    const format = (req.body.format || 'docx').toLowerCase();

    if (!file) {
        return res.status(400).json({ error: 'No PDF file uploaded.' });
    }

    try {
        // Extract content from PDF
        const extractedText = await extractContentFromPDF(file.path);

        let outputBuffer;
        let mimeType = '';
        let fileExtension = format;

        // Process based on target format
        if (format === 'docx') {
            outputBuffer = await generateWord(extractedText);
            mimeType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        } else if (format === 'xlsx') {
            outputBuffer = await generateExcel(extractedText);
            mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        } else if (format === 'pptx') {
            outputBuffer = await generatePPT(extractedText);
            mimeType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        } else if (format === 'txt') {
            outputBuffer = Buffer.from(extractedText, 'utf-8');
            mimeType = 'text/plain';
        } else {
            fs.unlinkSync(file.path); // Delete temp file
            return res.status(400).json({ error: 'Unsupported format requested.' });
        }

        // Delete uploaded temporary file
        fs.unlinkSync(file.path);

        // Send output file as response
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename=converted_output.${fileExtension}`);
        return res.send(outputBuffer);

    } catch (error) {
        if (file && fs.existsSync(file.path)) {
            fs.unlinkSync(file.path);
        }
        console.error('Conversion Error:', error);
        return res.status(500).json({ error: 'Failed to convert file. ' + error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});
