var crypto = require("crypto");
var Point = require("./point").Point;

function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;

  this.ecdh = crypto.createECDH(curve);
  this.ecdh.setPrivateKey(d);
}

PrivateKey.fromECDH = function(curve, ecdh) {
  var obj = Object.create(PrivateKey.prototype);
  obj.curve = curve;
  obj.d = ecdh.getPrivateKey();
  obj.ecdh = ecdh;
  return obj;
};

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof Point))
    throw new Error('publicKey must be a Point');
  return this.ecdh.computeSecret(publicKey.getEncoded());
};

PrivateKey.prototype.getPublicKey = function() {
  return Point.fromEncoded(this.curve, this.ecdh.getPublicKey());
};

function generateKeyPair(namedCurve) {
  var ecdh = crypto.createECDH(namedCurve);

  var publicKey = Point.fromEncoded(namedCurve, ecdh.generateKeys());
  var privateKey = PrivateKey.fromECDH(namedCurve, ecdh);

  return {
    publicKey: publicKey,
    privateKey: privateKey
  };
}

if (!crypto.createECDH) {
  throw "Node.js native ECDH not supported.";
}

module.exports = {
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
};
