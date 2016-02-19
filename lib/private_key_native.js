var native = require('bindings')('dhcurve.node');
var Point = require('./point').Point;

function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;
}

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof Point))
    throw new Error('publicKey must be a Point');
  return native.getSharedSecret(this.curve, this.d, publicKey);
};

PrivateKey.prototype.getPublicKey = function() {
  var publicKey = native.getPublicKey(this.curve, this.d);
  return new Point(this.curve, publicKey.x, publicKey.y);
};

function generateKeyPair(namedCurve) {
  var keys = native.generateKeyPair(namedCurve);

  var publicKey = new Point(namedCurve, keys.publicKey.x, keys.publicKey.y);
  var privateKey = new PrivateKey(namedCurve, keys.privateKey);

  return {
    publicKey: publicKey,
    privateKey: privateKey
  };
}

module.exports = {
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
};
