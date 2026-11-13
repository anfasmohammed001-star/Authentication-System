'use strict';

const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const frontendDir = path.join(rootDir, 'frontend');

const targetDirs = [
  rootDir,
  path.join(rootDir, 'dist'),
  path.join(rootDir, 'public'),
  path.join(rootDir, 'build'),
  frontendDir
];

// Ensure frontend has login.html
fs.copyFileSync(
  path.join(frontendDir, 'index.html'),
  path.join(frontendDir, 'login.html')
);

// Files to mirror to all target dirs
const filesToCopy = [
  'index.html',
  'login.html',
  'register.html',
  'dashboard.html',
  'styles.css',
  'app.js',
  '_redirects'
];

targetDirs.forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Copy files
  filesToCopy.forEach((file) => {
    const src = path.join(frontendDir, file);
    const dest = path.join(dir, file);
    if (src !== dest && fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
    }
  });

  // Copy assets folder
  const srcAssets = path.join(frontendDir, 'assets');
  const destAssets = path.join(dir, 'assets');
  if (srcAssets !== destAssets && fs.existsSync(srcAssets)) {
    if (!fs.existsSync(destAssets)) {
      fs.mkdirSync(destAssets, { recursive: true });
    }
    const assets = fs.readdirSync(srcAssets);
    assets.forEach((asset) => {
      fs.copyFileSync(path.join(srcAssets, asset), path.join(destAssets, asset));
    });
  }
});

console.log('Build complete: synchronized static assets to root, frontend, dist, public, and build directories.');

