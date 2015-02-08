var global = function() {
  return this;
}();

var native = require('../build/Release/dhcurve'),
    common = require('./common.js'),
    Promise = global.Promise || require('es6-promises'),
    _ = require('goal');
    
function PrivateKey(d, curve) {
  this.d = d;
  this.curve = curve;
}

_.inherits(PrivateKey, common.PrivateKey);

PrivateKey.prototype.getSharedSecret = function(publicKey) {
  if(!(publicKey instanceof common.Point))
    throw 'publicKey must be a Point';
  return native.getSharedSecret(this.curve, d, publicKey);
 };

function generateKeyPair(namedCurve) {
  if(_.typeOf(namedCurve) !== 'string')
    throw 'Invalid curve name';
  return new Promise(function(resolve, reject) {
    var keypair = native.generateKeyPair(namedCurve);
  
    var publicKey = Object.create(common.Point.prototype);
    _.mixin(publicKey, keypair.publicKey);
    publicKey.curve = namedCurve;
  
    var privateKey = new PrivateKey(keypair.privateKey, namedCurve);
  
    resolve({
      privateKey: privateKey,
      publicKey: publicKey
    });
  });
}

module.exports = _.mixin({}, common, {
  PrivateKey: PrivateKey,
  generateKeyPair: generateKeyPair
});
