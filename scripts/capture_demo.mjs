// Capture only the fictional local output; abort every external request.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {chromium} from 'playwright';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'out');
const images = path.join(root, 'docs', 'images');
fs.mkdirSync(images, {recursive: true});
const result = {passed: false, views: 0, externalRequestsBlocked: 0, errors: [], screenshots: []};
const browser = await chromium.launch({headless: true});
try {
  for (const [size, viewport] of [['desktop', {width: 1360, height: 1050}], ['mobile', {width: 390, height: 844}]]) {
    const context = await browser.newContext({viewport});
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.protocol === 'file:' && path.dirname(fileURLToPath(url)) === output) return route.continue();
      result.externalRequestsBlocked++;
      return route.abort();
    });
    const page = await context.newPage();
    page.on('pageerror', error => result.errors.push({size, message: error.message}));
    await page.goto(pathToFileURL(path.join(output, 'index.html')).href);
    for (const [tab, title, image] of [
      ['overview', 'Collection and purpose', '01-overview.png'],
      ['validation', 'Detection checks', '02-detection-checks.png'],
      ['response', 'Incident review', '03-incident-review.png'],
    ]) {
      await page.getByRole('button', {name: title, exact: true}).click();
      if (!await page.locator('#' + tab).isVisible()) throw Error('Missing tab: ' + tab);
      const visible = await page.locator('main > section:visible').count();
      if (visible !== 1) throw Error('More than one task section is visible');
      if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2)) throw Error('Page overflow');
      if (tab === 'validation' && await page.locator('tbody tr').count() !== 12) throw Error('Missing fixture rows');
      if (tab === 'response' && !await page.getByText('DEMO-001 · Fictional local record', {exact: true}).isVisible()) throw Error('Missing fictional evidence label');
      result.views++;
      if (size === 'desktop' || tab === 'overview') {
        const name = size === 'desktop' ? image : '04-mobile-overview.png';
        await page.screenshot({path: path.join(images, name), fullPage: true});
        result.screenshots.push(name);
      }
    }
    await context.close();
  }
  result.passed = result.errors.length === 0 && result.externalRequestsBlocked === 0;
} finally {
  await browser.close();
  fs.writeFileSync(path.join(output, 'browser-review.json'), JSON.stringify(result, null, 2));
}
console.log(JSON.stringify(result));
if (!result.passed) process.exitCode = 1;
