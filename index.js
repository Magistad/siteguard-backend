const express = require('express');
const { chromium } = require('playwright');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

app.post('/generate-pdf', async (req, res) => {
  try {
    const html = req.body.html;
    if (!html) {
      return res.status(400).json({ error: 'Missing HTML content' });
    }

    const browser = await chromium.launch({
      headless: true,
    });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle' });

    const pdfBuffer = await page.pdf({ format: 'A4' });
    await browser.close();

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': 'attachment; filename=report.pdf',
    });
    res.send(pdfBuffer);
  } catch (err) {
    console.error('PDF generation failed:', err);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

app.get('/', (req, res) => {
  res.send('SiteGuard Backend is running');
});

app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
