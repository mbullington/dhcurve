var native = require('../build/Release/dhcurve'),
    common = require('./common.js'),
    Promise = Promise || require('es6-promises'),
    _ = require('goal');

function PrivateKey(curve, d) {
  this.curve = curve;
  this.d = d;
}

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof common.Point))
    throw 'publicKey must be a Point';
  return new Promise(function(resolve, reject) {
    var secret = native.getSharedSecret(this.curve, this.d, publicKey);
    resolve(secret);
  }.bind(this));
 };

function generateKeyPair(namedCurve) {
  if(_.typeOf(namedCurve) !== 'string')
    throw 'Invalid curve name';
  return new Promise(function(resolve, reject) {
    var keypair = native.generateKeyPair(namedCurve);

    var publicKey = Object.create(common.Point.prototype);
    _.mixin(publicKey, keypair.publicKey);
    publicKey.curve = namedCurve;

    var privateKey = new PrivateKey(namedCurve, keypair.privateKey);

    resolve({
      publicKey: publicKey,
      privateKey: privateKey
    });
  });
}

module.exports = _.mixin({}, common, {
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
});
