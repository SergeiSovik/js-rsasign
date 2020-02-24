/*
 * dsa.js - new DSA class
 *
 * Original work Copyright (c) 2016-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { jsonToASN1HEX } from "./asn1-1.0.js"
import { getRandomBigIntegerMinToMax, Signature } from "./crypto-1.1.js"
import { getVbyList, isASN1HEX } from "./asn1hex-1.1.js"
import { BigInteger } from "./../../js-bn/modules/jsbn.js"

/**
 * class for DSA signing and verification
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class.
 * Please use {@link Signature} class instead.
 * </p>
 * <p>
 * NOTE: Until jsrsasign 6.2.3, DSA class have used codes from openpgpjs library 1.0.0
 * licenced under LGPL licence. To avoid license issue dsa-2.0.js was re-written with
 * my own codes in jsrsasign 7.0.0. 
 * Some random number generators used in dsa-2.0.js was newly defined
 * in crypto-1.1.js. Now all of LGPL codes are removed.
 * </p>
 */
export class DSA {
	constructor() {
		/** @type {BigInteger | null} */ this.p = null;
		/** @type {BigInteger | null} */ this.q = null;
		/** @type {BigInteger | null} */ this.g = null;
		/** @type {BigInteger | null} */ this.y = null;
		/** @type {BigInteger | null} */ this.x = null;
		this.type = "DSA";
		this.isPrivate = false;
		this.isPublic = false;
	}

    /**
     * set DSA private key by key parameters of BigInteger object
     * @param {BigInteger} p prime P parameter
     * @param {BigInteger} q sub prime Q parameter
     * @param {BigInteger} g base G parameter
     * @param {BigInteger} y public key Y or null
     * @param {BigInteger} x private key X
     */
	setPrivate(p, q, g, y, x) {
		this.isPrivate = true;
		this.p = p;
		this.q = q;
		this.g = g;
		this.y = y;
		this.x = x;
	}

    /**
     * set DSA private key by key parameters of hexadecimal string
     * @param {string} hP prime P parameter
     * @param {string} hQ sub prime Q parameter
     * @param {string} hG base G parameter
     * @param {string} hY public key Y or null
     * @param {string} hX private key X
     */
	setPrivateHex(hP, hQ, hG, hY, hX) {
		let biP, biQ, biG, biY, biX;
		biP = new BigInteger(hP, 16);
		biQ = new BigInteger(hQ, 16);
		biG = new BigInteger(hG, 16);
		if (typeof hY === "string" && hY.length > 1) {
			biY = new BigInteger(hY, 16);
		} else {
			biY = null;
		}
		biX = new BigInteger(hX, 16);
		this.setPrivate(biP, biQ, biG, biY, biX);
	}

    /**
     * set DSA public key by key parameters of BigInteger object
     * @param {BigInteger} p prime P parameter
     * @param {BigInteger} q sub prime Q parameter
     * @param {BigInteger} g base G parameter
     * @param {BigInteger} y public key Y
     */
	setPublic(p, q, g, y) {
		this.isPublic = true;
		this.p = p;
		this.q = q;
		this.g = g;
		this.y = y;
		this.x = null;
	}

    /**
     * set DSA public key by key parameters of hexadecimal string
     * @param {string} hP prime P parameter
     * @param {string} hQ sub prime Q parameter
     * @param {string} hG base G parameter
     * @param {string} hY public key Y
     */
	setPublicHex(hP, hQ, hG, hY) {
		let biP, biQ, biG, biY;
		biP = new BigInteger(hP, 16);
		biQ = new BigInteger(hQ, 16);
		biG = new BigInteger(hG, 16);
		biY = new BigInteger(hY, 16);
		this.setPublic(biP, biQ, biG, biY);
	}

    /**
     * sign to hashed message by this DSA private key object
     * @param {string} sHashHex hexadecimal string of hashed message
     * @return {string} hexadecimal string of ASN.1 encoded DSA signature value
     */
	signWithMessageHash(sHashHex) {
		let p = this.p; // parameter p
		let q = this.q; // parameter q
		let g = this.g; // parameter g
		//let y = this.y; // public key (p q g y)
		let x = this.x; // private key

		// NIST FIPS 186-4 4.5 DSA Per-Message Secret Number (p18)
		// 1. get random k where 0 < k < q
		let k = getRandomBigIntegerMinToMax(BigInteger.ONE().add(BigInteger.ONE()), q.subtract(BigInteger.ONE()));

		// NIST FIPS 186-4 4.6 DSA Signature Generation (p19)
		// 2. get z where the left most min(N, outlen) bits of Hash(M)
		let hZ = sHashHex.substr(0, q.bitLength() / 4);
		let z = new BigInteger(hZ, 16);

		// 3. get r where (g^k mod p) mod q, r != 0
		let r = (g.modPow(k, p)).mod(q);

		// 4. get s where k^-1 (z + xr) mod q, s != 0
		let s = (k.modInverse(q).multiply(z.add(x.multiply(r)))).mod(q);

		// 5. signature (r, s)
		return jsonToASN1HEX({
			"seq": [{ "int": { "bigint": r } }, { "int": { "bigint": s } }]
		});
	}

    /**
     * verify signature by this DSA public key object
     * @param {string} sHashHex hexadecimal string of hashed message
     * @param {string} hSigVal hexadecimal string of ASN.1 encoded DSA signature value
     * @return {boolean} true if the signature is valid otherwise false.
     */
	verifyWithMessageHash(sHashHex, hSigVal) {
		let p = this.p; // parameter p
		let q = this.q; // parameter q
		let g = this.g; // parameter g
		let y = this.y; // public key (p q g y)

		// 1. parse ASN.1 signature (r, s)
		let rs = this.parseASN1Signature(hSigVal);
		let r = rs[0];
		let s = rs[1];

		// NIST FIPS 186-4 4.6 DSA Signature Generation (p19)
		// 2. get z where the left most min(N, outlen) bits of Hash(M)
		let hZ = sHashHex.substr(0, q.bitLength() / 4);
		let z = new BigInteger(hZ, 16);

		// NIST FIPS 186-4 4.7 DSA Signature Validation (p19)
		// 3.1. 0 < r < q
		if (BigInteger.ZERO().compareTo(r) > 0 || r.compareTo(q) > 0)
			throw "invalid DSA signature";

		// 3.2. 0 < s < q
		if (BigInteger.ZERO().compareTo(s) >= 0 || s.compareTo(q) > 0)
			throw "invalid DSA signature";

		// 4. get w where w = s^-1 mod q
		let w = s.modInverse(q);

		// 5. get u1 where u1 = z w mod q
		let u1 = z.multiply(w).mod(q);

		// 6. get u2 where u2 = r w mod q
		let u2 = r.multiply(w).mod(q);

		// 7. get v where v = ((g^u1 y^u2) mod p) mod q
		let v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);

		// 8. signature is valid when v == r
		return v.compareTo(r) == 0;
	}

    /**
     * parse hexadecimal ASN.1 DSA signature value
     * @param {string} hSigVal hexadecimal string of ASN.1 encoded DSA signature value
     * @return {Array<BigInteger>} array [r, s] of DSA signature value. Both r and s are BigInteger.
     */
	parseASN1Signature(hSigVal) {
		try {
			let r = new BigInteger(getVbyList(hSigVal, 0, [0], "02"), 16);
			let s = new BigInteger(getVbyList(hSigVal, 0, [1], "02"), 16);
			return [r, s];
		} catch (ex) {
			throw "malformed ASN.1 DSA signature";
		}
	}

    /**
     * read an ASN.1 hexadecimal string of PKCS#1/5 plain DSA private key<br/>
     * @param {string} h hexadecimal string of PKCS#1/5 DSA private key
     */
	readPKCS5PrvKeyHex(h) {
		let hP, hQ, hG, hY, hX;

		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		try {
			hP = getVbyList(h, 0, [1], "02");
			hQ = getVbyList(h, 0, [2], "02");
			hG = getVbyList(h, 0, [3], "02");
			hY = getVbyList(h, 0, [4], "02");
			hX = getVbyList(h, 0, [5], "02");
		} catch (ex) {
			console.log("EXCEPTION:" + ex);
			throw "malformed PKCS#1/5 plain DSA private key";
		}

		this.setPrivateHex(hP, hQ, hG, hY, hX);
	}

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 plain DSA private key<br/>
     * @param {string} h hexadecimal string of PKCS#8 DSA private key
     */
	readPKCS8PrvKeyHex(h) {
		let hP, hQ, hG, hX;

		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		try {
			hP = getVbyList(h, 0, [1, 1, 0], "02");
			hQ = getVbyList(h, 0, [1, 1, 1], "02");
			hG = getVbyList(h, 0, [1, 1, 2], "02");
			hX = getVbyList(h, 0, [2, 0], "02");
		} catch (ex) {
			console.log("EXCEPTION:" + ex);
			throw "malformed PKCS#8 plain DSA private key";
		}

		this.setPrivateHex(hP, hQ, hG, null, hX);
	}

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 plain DSA private key<br/>
     * @param {string} h hexadecimal string of PKCS#8 DSA private key
     */
	readPKCS8PubKeyHex(h) {
		let hP, hQ, hG, hY;

		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		try {
			hP = getVbyList(h, 0, [0, 1, 0], "02");
			hQ = getVbyList(h, 0, [0, 1, 1], "02");
			hG = getVbyList(h, 0, [0, 1, 2], "02");
			hY = getVbyList(h, 0, [1, 0], "02");
		} catch (ex) {
			console.log("EXCEPTION:" + ex);
			throw "malformed PKCS#8 DSA public key";
		}

		this.setPublicHex(hP, hQ, hG, hY);
	}

    /**
     * read an ASN.1 hexadecimal string of X.509 DSA public key certificate<br/>
     * @param {string} h hexadecimal string of X.509 DSA public key certificate
     * @param {number} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
     */
	readCertPubKeyHex(h, nthPKI) {
		if (nthPKI !== 5) nthPKI = 6;
		let hP, hQ, hG, hY;

		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		try {
			hP = getVbyList(h, 0, [0, nthPKI, 0, 1, 0], "02");
			hQ = getVbyList(h, 0, [0, nthPKI, 0, 1, 1], "02");
			hG = getVbyList(h, 0, [0, nthPKI, 0, 1, 2], "02");
			hY = getVbyList(h, 0, [0, nthPKI, 1, 0], "02");
		} catch (ex) {
			console.log("EXCEPTION:" + ex);
			throw "malformed X.509 certificate DSA public key";
		}

		this.setPublicHex(hP, hQ, hG, hY);
	}
}
