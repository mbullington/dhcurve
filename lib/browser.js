var common = require('./common.js'),
    _ = require('goal');

var global = function() {
  return this;
}();

var NamedCurve = {
  'prime256v1': 'P-256'
};

function urlSafe(message) {
    return _.replaceAll(_.replaceAll(_.replaceAll(message.toString('base64'), '+', '-'), '/', '_'), '=', '');
}

function generateKeyPair(namedCurve) {
  return new Promise(function(resolve, reject) {
    global.crypto.subtle.generateKey({
      name: 'ECDH',
      namedCurve: NamedCurve[namedCurve] || namedCurve
    }, true, ['deriveBits']).then(function(keypair) {
      Promise.all([
        global.crypto.subtle.exportKey('jwk', keypair.publicKey),
        global.crypto.subtle.exportKey('jwk', keypair.privateKey)
      ]).then(function(values) {
        var publicKey = values[0];
        var privateKey = values[1];

        var privateObj = Object.create({
          getSharedSecret: function(p) {
            if(!(p instanceof common.Point))
              throw 'publicKey must be a Point';
            return new Promise(function(sresolve, sreject) {
              global.crypto.subtle.importKey('jwk', {
                crv: NamedCurve[p.curve] || namedCurve,
                ext: true,
                kty: 'EC',
                x: urlSafe(p.x),
                y: urlSafe(p.y)
              }, {
                name: 'ECDH',
                namedCurve: NamedCurve[p.curve] || namedCurve
              }, false, []).then(function(pObj) {
                global.crypto.subtle.deriveBits({
                  name: 'ecdh',
                  public: pObj
                }, keypair.privateKey, new Buffer(privateKey.d, 'base64').length).then(function(secret) {
                  sresolve(new Buffer(secret));
                }).catch(function(e) {
                  throw e;
                })
              }).catch(function(e) {
                sreject(e);
              });
            })
          }
        });

        privateObj.curve = namedCurve;

        resolve({
          publicKey: new common.Point(namedCurve, new Buffer(publicKey.x, 'base64'), new Buffer(publicKey.y, 'base64')),
          privateKey: privateObj
        });
      }).catch(function(e) {
        throw e;
      });
    }).catch(function(e) {
      reject(e);
    });
  });
}

module.exports = _.mixin({
  generateKeyPair: generateKeyPair
}, common);
