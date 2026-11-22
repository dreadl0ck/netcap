// A public URL keeps the app and sandboxed charts on the same font files.
const stylesheet = document.createElement('link');
stylesheet.rel = 'stylesheet';
stylesheet.href = '/static/fonts/noto-sans-sc/index.css';
const loaded = new Promise(resolve => {
  stylesheet.addEventListener('load', resolve, { once: true });
  stylesheet.addEventListener('error', resolve, { once: true });
});
document.head.append(stylesheet);
// Canvas renderers cache text metrics on first paint; make offline faces ready first.
if (document.fonts) {
  await loaded;
  await Promise.allSettled([...document.fonts].filter(face => face.family.includes('Noto Sans SC Variable')).map(face => face.load()));
}
export {};
