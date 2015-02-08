var d = require('../lib/index.js');
d.generateKeyPair(d.NamedCurve.P256).then(function(keypair1) {
  console.log(keypair1);
  
  d.generateKeyPair(d.NamedCurve.P256).then(function(keypair2) {
    console.log(keypair1.privateKey.getSharedSecret(keypair2.publicKey));
  }).catch(function(e) {
    console.log(e);
  });
}).catch(function(e) {
  console.log(e);
});
