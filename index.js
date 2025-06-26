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

console.log('Lighthouse typeof:', typeof lighthouse, 'keys:', Object.keys(lighthouse));

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

// Security headers
async function getSecurityHeaders(url) {
  try {
    const resp = await fetch(url, { method: 'GET', redirect: 'manual' });
    const headers = resp.headers.raw();
    const expected = [
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'content-security-policy',
      'permissions-policy',
      'server',
      'x-powered-by'
    ];
    let found = {};
    expected.forEach(h => {
      found[h] = headers[h] ? headers[h][0] : null;
    });
    return found;
  } catch (err) {
    return { error: err.message };
  }
}

// HTTPS and SSL check
async function checkHttps(url) {
  try {
    let parsed = urlModule.parse(url);
    let baseDomain = parsed.hostname;
    const httpUrl = `http://${baseDomain}`;
    let redirectedToHttps = false;
    try {
      const resp = await fetch(httpUrl, { method: 'GET', redirect: 'manual' });
      const location = resp.headers.get('location');
      if (location && location.startsWith('https://')) {
        redirectedToHttps = true;
      }
    } catch (e) {
      redirectedToHttps = true;
    }
    return new Promise((resolve) => {
      const options = {
        host: baseDomain,
        port: 443,
        method: 'GET',
        rejectUnauthorized: false,
      };
      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        resolve({
          redirectedToHttps,
          ssl: {
            subject: cert.subject,
            issuer: cert.issuer,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            valid: res.socket.authorized,
            protocol: res.socket.getProtocol ? res.socket.getProtocol() : undefined
          }
        });
      });
      req.on('error', (e) => {
        resolve({ redirectedToHttps, ssl: { error: e.message } });
      });
      req.end();
    });
  } catch (err) {
    return { error: err.message };
  }
}

// Safe Browsing
async function checkSafeBrowsing(url) {
  if (!SAFE_BROWSING_KEY) {
    return { status: 'skipped', reason: 'No API key' };
  }
  try {
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`;
    const body = {
      client: { clientId: "siteguard", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE", "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const resp = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (data && data.matches && data.matches.length > 0) {
      return { safe: false, matches: data.matches };
    } else {
      return { safe: true };
    }
  } catch (err) {
    return { error: err.message };
  }
}

// WHOIS / Domain age
async function getWhoisInfo(url) {
  try {
    const parsed = urlModule.parse(url);
    const domain = parsed.hostname || url;
    const whoisData = await whois(domain);
    const created = whoisData.creationDate || whoisData.created || whoisData['Creation Date'] || whoisData['created'];
    const registrar = whoisData.registrar || whoisData['Registrar'] || null;
    let domainAgeYears = null;
    if (created) {
      const createdDate = new Date(created);
      const now = new Date();
      domainAgeYears = ((now - createdDate) / (1000 * 60 * 60 * 24 * 365)).toFixed(2);
    }
    return { domain, registrar, created, domainAgeYears, raw: whoisData };
  } catch (err) {
    return { error: err.message };
  }
}

// Tracker, analytics, cookie detection
async function scanForTrackersAndCookies(url) {
  try {
    const resp = await fetch(url, { method: 'GET' });
    const html = await resp.text();
    const trackers = [
      { name: "Google Analytics", pattern: /www\.google-analytics\.com|gtag\(\'config\'/ },
      { name: "Google Tag Manager", pattern: /www\.googletagmanager\.com/ },
      { name: "Facebook Pixel", pattern: /connect\.facebook\.net|fbq\(/ },
      { name: "Hotjar", pattern: /static\.hotjar\.com/ },
      { name: "Segment", pattern: /cdn\.segment\.com/ },
      { name: "Matomo", pattern: /matomo\.js/ },
      { name: "HubSpot", pattern: /js\.hs-scripts\.com/ },
      { name: "Mixpanel", pattern: /cdn\.mixpanel\.com/ },
      { name: "Amplitude", pattern: /cdn\.amplitude\.com/ },
      { name: "Sentry", pattern: /browser\.sentry-cdn\.com/ },
      { name: "LinkedIn Insights", pattern: /snap\.licdn\.com/ },
      { name: "Twitter Ads", pattern: /static\.ads-twitter\.com/ }
    ];
    const cookieKeywords = [
      "cookie consent", "cookie banner", "cookie popup",
      "accept cookies", "this website uses cookies", "manage your cookie preferences"
    ];
    const privacyPolicyRegex = /<a [^>]*href="[^"]*privacy[^"]*"/i;
    let foundTrackers = [];
    for (const t of trackers) {
      if (t.pattern.test(html)) foundTrackers.push(t.name);
    }
    let foundCookieBanner = cookieKeywords.some(keyword =>
      html.toLowerCase().includes(keyword)
    );
    let foundPrivacyPolicy = privacyPolicyRegex.test(html);
    return {
      trackers: foundTrackers,
      cookieBanner: foundCookieBanner,
      privacyPolicy: foundPrivacyPolicy,
      html // for tech/outdated library checks
    };
  } catch (err) {
    return { error: err.message, html: '' };
  }
}

// Tech stack / JS libraries
function detectTechStack(headers, html) {
  const stack = [];
  if (headers['server']) stack.push(`Server: ${headers['server']}`);
  if (headers['x-powered-by']) stack.push(`X-Powered-By: ${headers['x-powered-by']}`);
  if (html) {
    if (html.includes('wp-content/')) stack.push('WordPress');
    if (html.match(/drupal\.js/i)) stack.push('Drupal');
    if (html.match(/shopify\.com/i)) stack.push('Shopify');
    if (html.match(/Magento/i)) stack.push('Magento');
    if (html.match(/\/static\/js\//i) && html.match(/react/i)) stack.push('React');
    if (html.match(/jquery/i)) stack.push('jQuery');
    if (html.match(/vue(\.js)?/i)) stack.push('Vue.js');
    if (html.match(/angular/i)) stack.push('Angular');
    if (html.match(/bootstrap/i)) stack.push('Bootstrap');
  }
  return stack;
}

// Outdated JS library detection (very basic MVP)
function detectOutdatedLibraries(html) {
  const results = [];
  if (html.match(/jquery-1\.[0-9.]+\.js/i)) results.push('jQuery 1.x (outdated)');
  if (html.match(/jquery-2\.[0-9.]+\.js/i)) results.push('jQuery 2.x (outdated)');
  if (html.match(/angular-1\.[0-9.]+\.js/i)) results.push('AngularJS 1.x (outdated)');
  if (html.match(/bootstrap-3\.[0-9.]+\.js/i)) results.push('Bootstrap 3.x (outdated)');
  return results;
}

// AbuseIPDB check
async function checkAbuseIPDB(url) {
  if (!ABUSEIPDB_KEY) {
    return { status: 'skipped', reason: 'No API key' };
  }
  try {
    const parsed = urlModule.parse(url);
    const domain = parsed.hostname;
    const ip = await new Promise((resolve, reject) => {
      dns.lookup(domain, (err, address) => {
        if (err) reject(err);
        else resolve(address);
      });
    });
    const apiUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`;
    const resp = await fetch(apiUrl, {
      headers: { Key: ABUSEIPDB_KEY, Accept: "application/json" }
    });
    const data = await resp.json();
    return data.data || data;
  } catch (err) {
    return { error: err.message };
  }
}

// Sensitive file/config exposure scan
async function scanSensitiveFiles(url) {
  try {
    const parsed = urlModule.parse(url);
    const base = `${parsed.protocol}//${parsed.hostname}`;
    const paths = [
      '/.git/config', '/.env', '/config.php', '/config.json', '/wp-config.php', '/admin/.env',
      '/robots.txt', '/sitemap.xml'
    ];
    let found = [];
    for (const path of paths) {
      try {
        const resp = await fetch(base + path, { method: 'GET' });
        if (resp.status === 200) {
          const text = await resp.text();
          if ((path === '/.git/config' && text.includes('[core]')) ||
              (path.endsWith('.env') && text.match(/DB_HOST|SECRET/i)) ||
              (path.endsWith('wp-config.php') && text.match(/define\('DB_/)) ||
              (path.endsWith('config.php') && text.match(/define\('DB_/))) {
            found.push(path);
          }
          if (path === '/robots.txt' || path === '/sitemap.xml') {
            found.push(path);
          }
        }
      } catch (e) { }
    }
    return found;
  } catch (err) {
    return { error: err.message };
  }
}

// Directory listing check
async function checkDirectoryListing(url) {
  try {
    const parsed = urlModule.parse(url);
    const base = `${parsed.protocol}//${parsed.hostname}`;
    const dirs = ['/', '/admin/', '/uploads/', '/images/'];
    let results = [];
    for (const dir of dirs) {
      try {
        const resp = await fetch(base + dir, { method: 'GET' });
        if (resp.status === 200) {
          const text = await resp.text();
          if (text.match(/Index of/i) || text.match(/Directory listing for/i)) {
            results.push(dir);
          }
        }
      } catch (e) { }
    }
    return results;
  } catch (err) {
    return { error: err.message };
  }
}

app.post('/scan', async (req, res) => {
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
    // Use empty string if html is missing
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
