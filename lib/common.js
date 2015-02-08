/*
 * Only supports NIST-recomended curves,
 * following the limitations of the Web Crypto API.
 */
var NamedCurve = {
  "P256": 0,
  "P384": 1,
  "P521": 2
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
  Point: Point
};
