var d = require('../lib/index.js');
d.generateKeyPair(d.NamedCurve.P256).then(function(result) {
  console.log(result);
}).catch(function(e) {
  console.log(e);
});
