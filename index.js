const express = require('express');
const { chromium } = require('playwright');
const cors = require('cors');
const lighthouse = require('lighthouse/core/index.cjs');
const chromeLauncher = require('chrome-launcher');
const fetch = require('node-fetch');
const https = require('https');
const dns = require('dns');
const urlModule = require('url');
const fs = require('fs');
const whois = require('whois-json');

const app = express();
const PORT = process.env.PORT || 3001;

// --- Load API keys from file ---
let SAFE_BROWSING_KEY = '';
try {
  SAFE_BROWSING_KEY = fs.readFileSync('./safebrowsing.key', 'utf-8').trim();
  console.log('Safe Browsing API key loaded.');
} catch (e) {
  console.warn('Safe Browsing API key not found. Malware checks will be disabled.');
}
let ABUSEIPDB_KEY = '';
try {
  ABUSEIPDB_KEY = fs.readFileSync('./abuseipdb.key', 'utf-8').trim();
  console.log('AbuseIPDB API key loaded.');
} catch (e) {
  console.warn('AbuseIPDB API key not found. IP reputation checks will be skipped.');
}

app.use(cors());
app.use(express.json());

app.post('/generate-pdf', async (req, res) => {
  try {
    const html = req.body.html;
    if (!html) {
      return res.status(400).json({ error: 'Missing HTML content' });
    }
    const browser = await chromium.launch({ headless: true });
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

// All utility functions remain unchanged...

// (Paste in all your previous utility functions here as before)
// (getSecurityHeaders, checkHttps, checkSafeBrowsing, getWhoisInfo, scanForTrackersAndCookies, detectTechStack, detectOutdatedLibraries, checkAbuseIPDB, scanSensitiveFiles, checkDirectoryListing)

app.post('/scan', async (req, res) => {
  // Use only the POSTed URL; no fallback, no default, no hardcoded test value!
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL in request body' });
  let chrome;
  try {
    const [
      securityHeaders,
      httpsCheck,
      safeBrowsing,
      whoisInfo,
      trackerCookieResult,
      abuseipdb,
      sensitiveFiles,
      directoryListing
    ] = await Promise.all([
      getSecurityHeaders(url),
      checkHttps(url),
      checkSafeBrowsing(url),
      getWhoisInfo(url),
      scanForTrackersAndCookies(url),
      checkAbuseIPDB(url),
      scanSensitiveFiles(url),
      checkDirectoryListing(url)
    ]);
    const safeHtml = trackerCookieResult && trackerCookieResult.html ? trackerCookieResult.html : '';
    const techStack = detectTechStack(securityHeaders, safeHtml);
    const outdatedLibs = detectOutdatedLibraries(safeHtml);
    chrome = await chromeLauncher.launch({ chromeFlags: ['--headless', '--no-sandbox'] });
    const options = {
      logLevel: 'info',
      output: 'json',
      onlyCategories: ['performance', 'accessibility', 'seo', 'best-practices'],
      port: chrome.port,
    };
    const runnerResult = await lighthouse(url, options);
    await chrome.kill();
    const categories = runnerResult.lhr.categories;
    const audits = runnerResult.lhr.audits;
    res.json({
      summary: {
        performance: categories.performance.score,
        accessibility: categories.accessibility.score,
        seo: categories.seo.score,
        bestPractices: categories['best-practices'].score,
      },
      security: {
        headers: securityHeaders,
        https: httpsCheck,
        safeBrowsing: safeBrowsing,
        whois: whoisInfo,
        trackersAndCookies: {
          trackers: trackerCookieResult.trackers,
          cookieBanner: trackerCookieResult.cookieBanner,
          privacyPolicy: trackerCookieResult.privacyPolicy
        },
        techStack,
        outdatedLibraries: outdatedLibs,
        abuseipdb,
        sensitiveFiles,
        directoryListing
      },
      audits: {
        'is-on-https': audits['is-on-https']?.score,
        'viewport': audits['viewport']?.score,
        'robots-txt': audits['robots-txt']?.score,
        'meta-description': audits['meta-description']?.score,
      },
      fullReport: runnerResult.lhr,
    });
  } catch (err) {
    if (chrome) await chrome.kill();
    console.error('Scan failed:', err);
    res.status(500).json({ error: 'Scan failed', details: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
