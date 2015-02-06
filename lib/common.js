/*
 * Only supports NIST-recomended curves,
 * following the limitations of the Web Crypto API.
 */
var NamedCurve = {
  "P-256": 0,
  "P-384": 1,
  "P-521": 2
}

function PublicKey() {

}

function PrivateKey() {

}

function Point() {

}

Point.prototype.toBuffer = function(compressed) {

};

module.exports = {
  NamedCurve: NamedCurve,
  PublicKey: PublicKey,
  PrivateKey: PrivateKey,
  Point: Point
};
