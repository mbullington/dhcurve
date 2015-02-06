var native = require('../build/Release/dhcurve'),
    common = require('./common.js'),
    Promise = require('es6-promises'),
    _ = require('goal');

function generateKeyPair() {

}

module.exports = _.mixin({
  generateKeyPair: generateKeyPair
}, common);
