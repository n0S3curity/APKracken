import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const ignoredDirectories = new Set(['.git', '.mintlify', 'node_modules']);

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await walk(absolute)));
    else if (entry.isFile()) files.push(absolute);
  }
  return files;
}

function relativePath(file) {
  return path.relative(root, file).split(path.sep).join('/');
}

function pageRoute(file) {
  const relative = relativePath(file).replace(/\.(?:md|mdx)$/i, '');
  return relative.endsWith('/index') ? relative.slice(0, -'/index'.length) : relative;
}

function internalPath(target) {
  if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) return null;
  const pathname = target.split(/[?#]/, 1)[0].replace(/\/$/, '');
  return pathname || '/';
}

function navigationPages(value, found = []) {
  if (Array.isArray(value)) {
    for (const item of value) navigationPages(item, found);
    return found;
  }
  if (!value || typeof value !== 'object') return found;
  for (const [key, child] of Object.entries(value)) {
    if (key === 'pages' && Array.isArray(child)) {
      for (const page of child) {
        if (typeof page === 'string') found.push(page.replace(/^\//, '').replace(/\/$/, ''));
        else navigationPages(page, found);
      }
    } else {
      navigationPages(child, found);
    }
  }
  return found;
}

function contentTargets(content) {
  const targets = [];
  const patterns = [/!?\[[^\]]*\]\(\s*(\/[^\s)]+)(?:\s+["'][^"']*["'])?\s*\)/g, /(?:href|src)=["'](\/[^"']*)["']/g];
  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) targets.push(match[1]);
  }
  return targets;
}

const allFiles = await walk(root);
const pageFiles = allFiles.filter((file) => /\.(?:md|mdx)$/i.test(file));
const routes = new Set(pageFiles.map(pageRoute));
const assets = new Set(allFiles.map((file) => `/${relativePath(file)}`));
const config = JSON.parse(await readFile(path.join(root, 'docs.json'), 'utf8'));
const errors = [];
let checkedReferences = 0;

function targetExists(target) {
  const normalized = internalPath(target);
  if (!normalized || normalized === '/') return true;
  return routes.has(normalized.slice(1)) || assets.has(normalized);
}

for (const page of navigationPages(config.navigation)) {
  checkedReferences += 1;
  if (!routes.has(page)) errors.push(`docs.json navigation references missing page: ${page}`);
}

for (const file of pageFiles) {
  const content = await readFile(file, 'utf8');
  for (const target of contentTargets(content)) {
    checkedReferences += 1;
    if (!targetExists(target)) errors.push(`${relativePath(file)} links to missing target: ${target}`);
  }
}

for (const redirect of config.redirects || []) {
  const source = internalPath(redirect?.source);
  const destination = internalPath(redirect?.destination);
  checkedReferences += 1;
  if (!source) errors.push(`docs.json has an invalid redirect source: ${redirect?.source ?? ''}`);
  else if (routes.has(source.slice(1))) errors.push(`redirect source still exists as a page: ${source}`);
  if (!destination || !targetExists(destination)) {
    errors.push(`redirect destination does not exist: ${redirect?.destination ?? ''}`);
  }
}

if (errors.length) {
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log(
    `Docs links OK: ${pageFiles.length} pages, ${checkedReferences} internal references, ${(config.redirects || []).length} redirects.`
  );
}
