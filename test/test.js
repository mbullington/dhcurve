var assert = require('better-assert'),
    ecdh = require('../lib/index.js');

describe('PrivateKey', function() {
  it('getSharedSecret()', function() {
    ecdh.generateKeyPair(ecdh.NamedCurve.P256).then(function(keypair1) {
      ecdh.generateKeyPair(ecdh.NamedCurve.P256).then(function(keypair2) {
        var secret1 = keypair1.privateKey.getSharedSecret(keypair2.publicKey);
        var secret2 = keypair2.privateKey.getSharedSecret(keypair1.publicKey);
        assert(secret1.toString('hex') !== secret2.toString('hex'));
      }).catch(function(e) {
        throw e;
      });
    }).catch(function(e) {
      throw e;
    });
  });
  
  it('getSharedSecret2()', function() {
    var privateKey = new ecdh.PrivateKey(ecdh.NamedCurve.P256, new Buffer('M6S41GAL0gH0I97Hhy7A2-icf8dHnxXPmYIRwem03HE', 'base64'));
    var publicKey = new ecdh.Point(ecdh.NamedCurve.P256, new Buffer('BCVrEhPXmozrKAextseekQauwrRz3lz2sj56td9j09Oajar0RoVR5Uo95AVuuws1vVEbDzhOUu7freU0BXD759U', 'base64'))
  
    var secret = privateKey.getSharedSecret(publicKey);
    var secretTest = new Buffer('116128c016cf380933c4b40ffeee8ef5999167f5c3d49298ba2ebfd0502e74e3', 'base64');
    assert(secret.toString('hex') === secretTest.toString('hex'));
  });
});