/*
 * splitted from bitcoin-lib/ecdsa.js
 *
 * version 1.0.0 is the original of bitcoin-lib/ecdsa.js
 *
 * Original work Copyright (c) Stefan Thomas | https://github.com/bitcoinjs/bitcoinjs-lib
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

ECFieldElementFp.prototype.export function getByteLength() {
  return Math.floor((this.toBigInteger().bitLength() + 7) / 8);
};

ECPointFp.prototype.export function getEncoded(compressed) {
  let integerToBytes = function(i, len) {
    let bytes = i.toByteArrayUnsigned();

    if (len < bytes.length) {
      bytes = bytes.slice(bytes.length-len);
    } else while (len > bytes.length) {
      bytes.unshift(0);
    }
    return bytes;
  };

  let x = this.getX().toBigInteger();
  let y = this.getY().toBigInteger();

  // Get value as a 32-byte Buffer
  // Fixed length based on a patch by bitaddress.org and Casascius
  let enc = integerToBytes(x, 32);

  if (compressed) {
    if (y.isEven()) {
      // Compressed even pubkey
      // M = 02 || X
      enc.unshift(0x02);
    } else {
      // Compressed uneven pubkey
      // M = 03 || X
      enc.unshift(0x03);
    }
  } else {
    // Uncompressed pubkey
    // M = 04 || X || Y
    enc.unshift(0x04);
    enc = enc.concat(integerToBytes(y, 32));
  }
  return enc;
};

ECPointFp.export function decodeFrom(curve, enc) {
  let type = enc[0];
  let dataLen = enc.length-1;

  // Extract x and y as byte arrays
  let xBa = enc.slice(1, 1 + dataLen/2);
  let yBa = enc.slice(1 + dataLen/2, 1 + dataLen);

  // Prepend zero byte to prevent interpretation as negative integer
  xBa.unshift(0);
  yBa.unshift(0);

  // Convert to BigIntegers
  let x = new BigInteger(xBa);
  let y = new BigInteger(yBa);

  // Return point
  return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
};

/*
 */
ECPointFp.export function decodeFromHex(curve, encHex) {
  let type = encHex.substr(0, 2); // shall be "04"
  let dataLen = encHex.length - 2;

  // Extract x and y as byte arrays
  let xHex = encHex.substr(2, dataLen / 2);
  let yHex = encHex.substr(2 + dataLen / 2, dataLen / 2);

  // Convert to BigIntegers
  let x = new BigInteger(xHex, 16);
  let y = new BigInteger(yHex, 16);

  // Return point
  return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
};

ECPointFp.prototype.export function add2D(b) {
  if(this.isInfinity()) return b;
  if(b.isInfinity()) return this;

  if (this.x.equals(b.x)) {
    if (this.y.equals(b.y)) {
      // this = b, i.e. this must be doubled
      return this.twice();
    }
    // this = -b, i.e. the result is the point at infinity
    return this.curve.getInfinity();
  }

  let x_x = b.x.subtract(this.x);
  let y_y = b.y.subtract(this.y);
  let gamma = y_y.divide(x_x);

  let x3 = gamma.square().subtract(this.x).subtract(b.x);
  let y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

  return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.export function twice2D() {
  if (this.isInfinity()) return this;
  if (this.y.toBigInteger().signum() == 0) {
    // if y1 == 0, then (x1, y1) == (x1, -y1)
    // and hence this = -this and thus 2(x1, y1) == infinity
    return this.curve.getInfinity();
  }

  let TWO = this.curve.fromBigInteger(BigInteger.valueOf(2));
  let THREE = this.curve.fromBigInteger(BigInteger.valueOf(3));
  let gamma = this.x.square().multiply(THREE).add(this.curve.a).divide(this.y.multiply(TWO));

  let x3 = gamma.square().subtract(this.x.multiply(TWO));
  let y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

  return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.export function multiply2D(k) {
  if(this.isInfinity()) return this;
  if(k.signum() == 0) return this.curve.getInfinity();

  let e = k;
  let h = e.multiply(new BigInteger("3"));

  let neg = this.negate();
  let R = this;

  let i;
  for (i = h.bitLength() - 2; i > 0; --i) {
    R = R.twice();

    let hBit = h.testBit(i);
    let eBit = e.testBit(i);

    if (hBit != eBit) {
      R = R.add2D(hBit ? this : neg);
    }
  }

  return R;
};

ECPointFp.prototype.export function isOnCurve() {
  let x = this.getX().toBigInteger();
  let y = this.getY().toBigInteger();
  let a = this.curve.getA().toBigInteger();
  let b = this.curve.getB().toBigInteger();
  let n = this.curve.getQ();
  let lhs = y.multiply(y).mod(n);
  let rhs = x.multiply(x).multiply(x)
    .add(a.multiply(x)).add(b).mod(n);
  return lhs.equals(rhs);
};

ECPointFp.prototype.export function toString() {
  return '('+this.getX().toBigInteger().toString()+','+
    this.getY().toBigInteger().toString()+')';
};

/**
 * Validate an elliptic curve point.
 *
 * See SEC 1, section 3.2.2.1: Elliptic Curve Public Key Validation Primitive
 */
ECPointFp.prototype.export function validate() {
  let n = this.curve.getQ();

  // Check Q != O
  if (this.isInfinity()) {
    throw new Error("Point is at infinity.");
  }

  // Check coordinate bounds
  let x = this.getX().toBigInteger();
  let y = this.getY().toBigInteger();
  if (x.compareTo(BigInteger.ONE) < 0 ||
      x.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error('x coordinate out of bounds');
  }
  if (y.compareTo(BigInteger.ONE) < 0 ||
      y.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error('y coordinate out of bounds');
  }

  // Check y^2 = x^3 + ax + b (mod n)
  if (!this.isOnCurve()) {
    throw new Error("Point is not on the curve.");
  }

  // Check nQ = 0 (Q is a scalar multiple of G)
  if (this.multiply(n).isInfinity()) {
    // TODO: This check doesn't work - fix.
    throw new Error("Point is not a scalar multiple of G.");
  }

  return true;
};
