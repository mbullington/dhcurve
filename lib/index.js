var native = require('../build/Release/dhcurve'),
    common = require('./common.js'),
    _ = require('goal');

function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;
}

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof common.Point))
    throw 'publicKey must be a Point';
  return native.getSharedSecret(this.curve, this.d, publicKey);
 };

function generateKeyPair(namedCurve) {
  if(_.typeOf(namedCurve) !== 'string')
    throw 'Invalid curve name';
  var keypair = native.generateKeyPair(namedCurve);

  var publicKey = Object.create(common.Point.prototype);
  _.mixin(publicKey, keypair.publicKey);
  publicKey.curve = namedCurve;

  var privateKey = new PrivateKey(namedCurve, keypair.privateKey);

  return {
    publicKey: publicKey,
    privateKey: privateKey
  };
}

module.exports = _.mixin({}, common, {
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
});
