var point = require('./point');
var private_key;

// testing purposes only
// process.browser = true;

// avoiding loading private key on Browserify
if(!process.browser) {
  try {
    // will fail on Windows (OpenSSL problem), therefore use sjcl instead
    // TODO: If node.js version > 5.2.0, use native ECDH
    private_key = require('./private_key' + '_native');
  } catch(e) {}
}

if(!private_key) {
  private_key = require('./private_key_sjcl');
}

module.exports = {
  NamedCurve: point.NamedCurve,
  Point: point.Point,
  PrivateKey: private_key.PrivateKey,
  generateKeyPair: private_key.generateKeyPair
};
