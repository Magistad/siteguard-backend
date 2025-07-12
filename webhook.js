const express = require('express');
const fs = require('fs');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Memory store (can replace with DB or file later)
let paidUrls = new Set();

// Optional: Load from disk at startup
const FILE_PATH = './paid-urls.json';
if (fs.existsSync(FILE_PATH)) {
  try {
    paidUrls = new Set(JSON.parse(fs.readFileSync(FILE_PATH)));
    console.log('✅ Loaded paid URLs from disk');
  } catch (err) {
    console.warn('⚠️ Failed to load paid URLs, starting fresh');
  }
}

// Stripe webhook endpoint
router.post('/', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const url = session.metadata?.scanned_url;
    if (url) {
      paidUrls.add(url);
      fs.writeFileSync(FILE_PATH, JSON.stringify(Array.from(paidUrls), null, 2));
      console.log(`💰 Verified payment for: ${url}`);
    }
  }

  res.status(200).json({ received: true });
});

// Export paid URL checker
function isUrlPaid(url) {
  return paidUrls.has(url);
}

module.exports = { router, isUrlPaid };
