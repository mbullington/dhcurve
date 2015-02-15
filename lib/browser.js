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

function generateKeyPair(curve) {
  var keys = sjcl.ecc.basicKey.generateKeys('basicKey')(NamedCurve[curve] || curve);

  var privateObj = Object.create({
    getSharedSecret: function(point) {
      if(!(point instanceof common.Point))
        throw 'publicKey must be a Point';

      var curve = sjcl.ecc.curves['c' + (NamedCurve[point.curve] || point.curve)];

      var x = bufToBn(point.x);
      var y = bufToBn(point.y);

      var point = new sjcl.ecc.point(curve, x, y);

      var secret = sjcl.hash.sha256.hash(point.mult(keys.sec.get()));
      var buf = new Buffer(sjcl.codec.bytes.fromBits(secret));

      return buf;
    }
  });

  privateObj.curve = curve;

  return {
    publicKey: new common.Point(curve, bnToBuf(keys.pub._point.x), bnToBuf(keys.pub._point.y)),
    privateKey: privateObj
  };
}

module.exports = _.mixin({
  generateKeyPair: generateKeyPair
}, common);
