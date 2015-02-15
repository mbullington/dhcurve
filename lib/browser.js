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

// insecure 'PrivateKey' object.
// used for testing purposes, importing keys, etc.
function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;
}

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof common.Point))
    throw 'publicKey must be a Point';

  var curve = sjcl.ecc.curves['c' + (NamedCurve[publicKey.curve] || publicKey.curve)];

  var x = bufToBn(publicKey.x);
  var y = bufToBn(publicKey.y);

  var point = new sjcl.ecc.point(curve, x, y);
  var exponent = bufToBn(this.d);

  var secret = new Buffer(sjcl.codec.bytes.fromBits(point.mult(exponent).x.toBits()));
  return secret;
};

function generateKeyPair(curve) {
  var keys = sjcl.ecc.basicKey.generateKeys('basicKey')(NamedCurve[curve] || curve, 6);

  var privateObj = Object.create(_.mixin(Object.create(PrivateKey.prototype), {
    getSharedSecret: function(publicKey) {
      if(!(publicKey instanceof common.Point))
        throw 'publicKey must be a Point';

      var curve = sjcl.ecc.curves['c' + (NamedCurve[publicKey.curve] || publicKey.curve)];

      var x = bufToBn(publicKey.x);
      var y = bufToBn(publicKey.y);

      var point = new sjcl.ecc.point(curve, x, y);
      var secret = new Buffer(sjcl.codec.bytes.fromBits(point.mult(keys.sec._exponent).x.toBits()));

      return secret;
    }
  }));

  privateObj.curve = curve;

  return {
    publicKey: new common.Point(curve, bnToBuf(keys.pub._point.x), bnToBuf(keys.pub._point.y)),
    privateKey: privateObj
  };
}

module.exports = _.mixin({
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
}, common);
