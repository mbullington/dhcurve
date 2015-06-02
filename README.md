dhcurve [![Build Status](https://travis-ci.org/mbullington/dhcurve.svg?branch=master)](https://travis-ci.org/mbullington/dhcurve)
===

```
npm install dhcurve --save
```

dhcurve is a lower-level ECC and ECDH library for JavaScript. It works in the browser, on node.js 0.10.x, 0.12.x, and io.js. While running in node.js environment on \*nix platforms, dhcurve is backed by OpenSSL. In the browser (and in a node.js environment in Windows) it uses sjcl.

Contributing
===

As crypto peer review is very important, feel free to review and critique the code! Help make dhcurve better for everyone.

Examples
===

Examples can be found in test/test.js, or in example/example.js

```javascript
var curve = require('dhcurve');

var keypair1 = curve.generateKeyPair(curve.NamedCurve.P256);
var keypair2 = curve.generateKeyPair(curve.NamedCurve.P256);

keypair1.privateKey.getSharedSecret(keypair2.publicKey);
```
