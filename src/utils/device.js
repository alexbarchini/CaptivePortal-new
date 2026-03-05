function detectDeviceType(userAgent = '') {
  const ua = String(userAgent || '');

  if (/android/i.test(ua)) return 'Android';
  if (/iphone|ipad|ipod/i.test(ua)) return 'iOS';
  if (/windows nt/i.test(ua)) return 'Windows';
  if (/mac os x|macintosh/i.test(ua) && !/iphone|ipad|ipod/i.test(ua)) return 'macOS';
  if (/linux/i.test(ua) && !/android/i.test(ua)) return 'Linux';

  return 'Unknown';
}

module.exports = { detectDeviceType };
