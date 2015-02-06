var global = function() {
  return this;
}();

var native = require('../build/Release/dhcurve'),
    common = require('./common.js'),
    Promise = global.Promise || require('es6-promises'),
    _ = require('goal');

function generateKeyPair() {

}

module.exports = _.mixin({
  generateKeyPair: generateKeyPair
}, common);
