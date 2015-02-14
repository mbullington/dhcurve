var d = require('../lib/index.js');
d.generateKeyPair(d.NamedCurve.P256).then(function(keypair1) {
  console.log(keypair1);

  d.generateKeyPair(d.NamedCurve.P256).then(function(keypair2) {
    keypair1.privateKey.getSharedSecret(keypair2.publicKey).then(function(val) {
      console.log(val);
    }).catch(function(e) {
      console.log(e);
    });
  }).catch(function(e) {
    console.log(e);
  });
}).catch(function(e) {
  console.log(e);
});
