import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));

let browser;
try {
  browser = await chromium.launch({
    headless: false,
    args: [
      `--proxy-pac-url=${config.pacUrl}`,
      '--ignore-certificate-errors',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--host-resolver-rules=MAP direct.test 127.0.0.1',
    ],
  });

  const page = await browser.newPage();
  const checks = [
    [config.httpUrl, 'proxied-http'],
    [config.httpsUrl, 'proxied-https'],
    [config.directUrl, 'direct'],
  ];

  for (const [url, expected] of checks) {
    const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    assert.ok(response, `no response for ${url}`);
    assert.equal(response.status(), 200, `status for ${url}`);
    const body = (await page.textContent('body')).trim();
    assert.equal(body, expected, `body for ${url}`);
    console.log(`ok ${url}`);
  }
} finally {
  if (browser) await browser.close();
}
