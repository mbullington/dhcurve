try {
  var native = require('bindings')('dhcurve.node');
} catch(e) {
  module.exports = require('./browser.js');
}

if(typeof(native) !== 'undefined') {
  var common = require('./common.js'),
      _ = require('goal');

  function PrivateKey(curve, d) {
    this.curve = curve;
    this.d = d;
  }

  PrivateKey.prototype.getSharedSecret = function(publicKey) {
    if(!(publicKey instanceof common.Point))
      throw new Error('publicKey must be a Point');
    return native.getSharedSecret(this.curve, this.d, publicKey);
  };

  PrivateKey.prototype.getPublicKey = function() {
    var publicKey = native.getPublicKey(this.curve, this.d);
    return new common.Point(this.curve, publicKey.x, publicKey.y);
  };

  function generateKeyPair(namedCurve) {
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
}
