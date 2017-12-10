var curve = require('../lib/index.js');

var keypair1 = curve.generateKeyPair(curve.NamedCurve.P256);
console.log(keypair1);

var keypair2 = curve.generateKeyPair(curve.NamedCurve.P256);
var val = keypair1.privateKey.getSharedSecret(keypair2.publicKey);
console.log(val);
