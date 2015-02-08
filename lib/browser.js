var common = require('./common.js'),
    _ = require('goal');

var global = function() {
  return this;
}();

function generateKeyPair(namedCurve) {
  return new Promise(function(resolve, reject) {
    global.crypto.subtle.generateKey({
      name: 'ECDH',
      namedCurve: namedCurve
    }, true, ['deriveBits']).then(function(keypair) {
      var privateKey = global.crypto.subtle.exportKey("jwk", keypair.privateKey);
      var publicKey = global.crypto.subtle.exportKey("jwk", keypair.publicKey);
    });
  });
}

module.exports = _.mixin({
  generateKeyPair: generateKeyPair
}, common);
