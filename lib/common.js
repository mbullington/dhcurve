/*
 * Only supports NIST-recomended curves,
 * following the limitations of the Web Crypto API.
 */
var NamedCurve = {
  "P-256": 0,
  "P-384": 1,
  "P-521": 2
}

function Point(x, y) {
  this.x = x;
  this.y = y;
}

Point.prototype.equals = function(point) {
  return this.x.toString('hex') === point.x.toString('hex') &&
         this.y.toString('hex') === point.y.toString('hex');
}

Point.prototype.getEncoded = function(compressed) {

};

module.exports = {
  NamedCurve: NamedCurve,
  Point: Point
};
