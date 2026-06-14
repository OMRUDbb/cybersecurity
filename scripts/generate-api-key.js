#!/usr/bin/env node

/**
 * Generate a secure API key
 * Usage: node scripts/generate-api-key.js
 */

const crypto = require('crypto');

function generateApiKey() {
  const key = crypto.randomBytes(32).toString('hex');
  return key;
}

const apiKey = generateApiKey();

console.log('\n🔐 Generated API Key:\n');
console.log(apiKey);
console.log('\n📋 Add this to your .env file:\n');
console.log(`API_KEY=${apiKey}\n`);
console.log('✅ Keep this key safe and secure!\n');

module.exports = { generateApiKey };
