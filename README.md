dhcurve v1.0.0 [![Build Status](https://travis-ci.org/mbullington/dhcurve.svg?branch=master)](https://travis-ci.org/mbullington/dhcurve)
===

```
npm install dhcurve --save
```

dhcurve is a lower-level ECC and ECDH library for JavaScript. It works in the browser, on node.js 0.10.x, 0.12.x, and io.js. On node-like platforms, dhcurve is backed by OpenSSL. In the browser it uses sjcl.

Contributing

Examples
===

Examples can be found in test/test.js, or in example/example.js

```javascript
var curve = require('dhcurve');

var keypair1 = curve.generateKeyPair(curve.NamedCurve.P256);
var keypair2 = curve.generateKeyPair(curve.NamedCurve.P256);

keypair1.privateKey.getSharedSecret(keypair2.publicKey);
```

Future goals
===

- More functional helpers (curry, etc).
- Optional lazy loading functionality.
