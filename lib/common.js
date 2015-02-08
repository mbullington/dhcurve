/*
 * Only supports NIST-recomended curves,
 * following the limitations of the Web Crypto API.
 */
var NamedCurve = {
  'P256': 'prime256v1',
};

var PrivateKey = {};

function Point(curve, x, y) {
  this.curve = curve;
  this.x = x;
  this.y = y;
}

Point.fromEncoded = function(curve, encoded, compressed) {
  compressed = compressed || false;
  if(encoded[0] === 4) {
    var length = (encoded.length - 1) / 2;

    var x = new Buffer(length);
    var y = new Buffer(length);

    encoded.copy(x, 0, 1, 1 + length);
    encoded.copy(y, 0, 1 + length);

    return new Point(curve, x, y);
  } else {
    // TODO compressed
  }
};

Point.prototype.equals = function(point) {
  return this.x.toString('hex') === point.x.toString('hex') &&
         this.y.toString('hex') === point.y.toString('hex');
};

Point.prototype.getEncoded = function(compressed) {
  compressed = compressed || false;
  if(compressed) {
    // TODO
  } else {
    var buf = new Buffer(1 + this.x.length + this.y.length);

    buf.writeUInt8(0x04, 0);
    this.x.copy(buf, 1);
    this.y.copy(buf, 1 + this.x.length);

    return buf;
  }
};

module.exports = {
  NamedCurve: NamedCurve,
  PrivateKey: PrivateKey,
  Point: Point
};
