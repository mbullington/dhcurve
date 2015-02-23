var common = require('./common.js'),
    sjcl = require('../vendor/sjcl.js'),
    _ = require('goal');

var NamedCurve = {
  'prime256v1': 256
};

function urlSafe(message) {
  return _.replaceAll(_.replaceAll(_.replaceAll(message.toString('base64'), '+', '-'), '/', '_'), '=', '');
}

function bnToBuf(bn) {
  return new Buffer(sjcl.codec.bytes.fromBits(bn.toBits()));
}

function bufToBn(buf) {
  return sjcl.bn.fromBits(sjcl.codec.bytes.toBits(buf));
}

function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;
}

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof common.Point))
  throw new Error('publicKey must be a Point');

  var curve = sjcl.ecc.curves['c' + (NamedCurve[publicKey.curve] || publicKey.curve)];

  var x = bufToBn(publicKey.x);
  var y = bufToBn(publicKey.y);

  var point = new sjcl.ecc.point(curve, x, y);
  var exponent = bufToBn(this.d);

  var secret = new Buffer(sjcl.codec.bytes.fromBits(point.mult(exponent).x.toBits()));
  return secret;
};

PrivateKey.prototype.getPublicKey = function() {
  var exponent = bufToBn(this.d);
  var curve = sjcl.ecc.curves['c' + (NamedCurve[this.curve] || this.curve)];

  var publicKey =  curve.G.mult(exponent);
  var x = bnToBuf(publicKey.x);
  var y = bnToBuf(publicKey.y);

  return new common.Point(this.curve, x, y);
};

function generateKeyPair(curve) {
  var keys = sjcl.ecc.basicKey.generateKeys('basicKey')(NamedCurve[curve] || curve, 6);

  return {
    publicKey: new common.Point(curve, bnToBuf(keys.pub._point.x), bnToBuf(keys.pub._point.y)),
    privateKey: new PrivateKey(curve, bnToBuf(keys.sec._exponent))
  };
}

module.exports = _.mixin({
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
}, common);
