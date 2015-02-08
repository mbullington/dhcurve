var global = function() {
  return this;
}();

var PrivateKeyProto = {};

var native = require('../build/Release/dhcurve'),
    common = require('./common.js'),
    Promise = global.Promise || require('es6-promises'),
    _ = require('goal');

function generateKeyPair(namedCurve) {
  if(_.typeOf(namedCurve) !== 'number' || namedCurve % 1 !== 0)
    throw "NamedCurve must be an integer!";
  var keypair = native.generateKeyPair(namedCurve);
  
  var publicKey = Object.create(common.Point.prototype);
  _.mixin(publicKey, keypair.publicKey);
  
  // TODO
  var privateKey = {
  };
  
  _.mixin(privateKey, PrivateKeyProto);
  
  return {
    privateKey: Object.create(privateKey);
    publicKey: publicKey
  };
}

module.exports = _.mixin({
  generateKeyPair: generateKeyPair
}, common);
