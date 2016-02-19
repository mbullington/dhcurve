var sjcl = require('../vendor/sjcl.js');
var Point = require('./point').Point;

sjcl.plus = {
  // if no defined curve type, allow any sjcl type
  curveMappings: {
    'prime256v1': 256
  },
  buffer: {
    fromBn: function(bn) {
      return new Buffer(sjcl.codec.bytes.fromBits(bn));
    },
    toBn: function(buf) {
      return sjcl.bn.fromBits(sjcl.codec.bytes.toBits(buf));
    }
  }
};

function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;
}

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof Point))
    throw new Error('publicKey must be a Point');

  var curve = sjcl.ecc.curves['c' + (sjcl.plus.curveMappings[this.curve] || this.curve)];

  var x = sjcl.plus.buffer.toBn(publicKey.x);
  var y = sjcl.plus.buffer.toBn(publicKey.y);

  var point = new sjcl.ecc.point(curve, x, y);
  var exponent = sjcl.plus.buffer.toBn(this.d);

  return sjcl.plus.buffer.fromBn(point.mult(exponent).x.toBits());
};

PrivateKey.prototype.getPublicKey = function() {
  var exponent = sjcl.plus.buffer.toBn(this.d);
  var curve = sjcl.ecc.curves['c' + (sjcl.plus.curveMappings[this.curve] || this.curve)];

  var publicKey = curve.G.mult(exponent);

  var x = sjcl.plus.buffer.fromBn(publicKey.x.toBits());
  var y = sjcl.plus.buffer.fromBn(publicKey.y.toBits());

  return new Point(this.curve, x, y);
};

function generateKeyPair(curve) {
  var keys = sjcl.ecc.basicKey.generateKeys('basicKey')
    (sjcl.plus.curveMappings[curve] || curve, 0);

  var pub = keys.pub.get();
  var sec = keys.sec.get();

  return {
    publicKey: new Point(curve,
      sjcl.plus.buffer.fromBn(pub.x),
      sjcl.plus.buffer.fromBn(pub.y)),
    privateKey: new PrivateKey(curve, sjcl.plus.buffer.fromBn(sec))
  };
}

module.exports = {
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
};
