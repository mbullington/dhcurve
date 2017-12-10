var point = require('./point');
var private_key;

// testing purposes only
// process.browser = true;

// avoiding loading private key on Browserify
if(!process.browser) {
  try {
    // will throw if Node.js version doesn't support proper createECDH
    // if so, use sjcl fallback
    private_key = require('./private_key' + '_native');
  } catch(e) {
    console.log(e);
  }
}

if(!private_key) {
  console.log("Loading SJCL callback");
  private_key = require('./private_key_sjcl');
}

module.exports = {
  NamedCurve: point.NamedCurve,
  Point: point.Point,
  PrivateKey: private_key.PrivateKey,
  generateKeyPair: private_key.generateKeyPair
};
