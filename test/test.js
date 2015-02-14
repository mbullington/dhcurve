var assert = require('assert'),
    curve = require('../lib/index.js');

describe('PrivateKey', function() {
  describe('getSharedSecret()', function() {
    /*
    it('produces correct output', function() {
      var privateKey = new curve.PrivateKey(curve.NamedCurve.P256, new Buffer('M6S41GAL0gH0I97Hhy7A2-icf8dHnxXPmYIRwem03HE', 'base64'));
      var publicKey = curve.Point.fromEncoded(curve.NamedCurve.P256, new Buffer('BCVrEhPXmozrKAextseekQauwrRz3lz2sj56td9j09Oajar0RoVR5Uo95AVuuws1vVEbDzhOUu7freU0BXD759U', 'base64'));

      var secret = privateKey.getSharedSecret(publicKey);
      var secretTest = new Buffer('116128c016cf380933c4b40ffeee8ef5999167f5c3d49298ba2ebfd0502e74e3', 'hex');
      assert(secret.toString('hex') === secretTest.toString('hex'));
    });
    */

    it('is reversable', function(done) {
      curve.generateKeyPair(curve.NamedCurve.P256).then(function(keypair1) {
        curve.generateKeyPair(curve.NamedCurve.P256).then(function(keypair2) {
          Promise.all([
            keypair1.privateKey.getSharedSecret(keypair2.publicKey),
            keypair2.privateKey.getSharedSecret(keypair1.publicKey)
          ]).then(function(values) {
            assert(values[0].toString('hex') === values[1].toString('hex'));
            done();
          }).catch(function(e) {
            throw e;
          });
        }).catch(function(e) {
          throw e;
        });
      }).catch(function(e) {
        throw e;
      });
    });
  });
});

describe('Point', function() {
  /*
  it('fromEncoded() & getEncoded()', function() {
    var privateKey = new curve.PrivateKey(curve.NamedCurve.P256, new Buffer('M6S41GAL0gH0I97Hhy7A2-icf8dHnxXPmYIRwem03HE', 'base64'));
    var publicKey = curve.Point.fromEncoded(curve.NamedCurve.P256, new Buffer('BCVrEhPXmozrKAextseekQauwrRz3lz2sj56td9j09Oajar0RoVR5Uo95AVuuws1vVEbDzhOUu7freU0BXD759U', 'base64'));

    assert(publicKey.getEncoded().toString('base64').replace("=", "") === 'BCVrEhPXmozrKAextseekQauwrRz3lz2sj56td9j09Oajar0RoVR5Uo95AVuuws1vVEbDzhOUu7freU0BXD759U');
  });
  */

  it('equals()', function(done) {
    curve.generateKeyPair(curve.NamedCurve.P256).then(function(keypair) {
      var point = new curve.Point(curve.NamedCurve.P256, keypair.publicKey.x, keypair.publicKey.y);
      assert(point.equals(keypair.publicKey));
      done();
    });
  });
});
