/*
 * rsa2.js
 *
 * Original work Copyright (c) ? Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

/*
 * rsapem.js - Cryptographic Algorithm Provider class
 *
 * Original work Copyright (c) 2013-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/*
 * rsa-sign.js - adding signing functions to RSAKeyEx class.
 *
 * Original work Copyright (c) 2010-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { MessageDigest, hashHex, hashString, getPaddedDigestInfoHex, DIGESTINFOHEAD } from "./crypto-1.1.js"
import { rstrtohex, hextorstr } from "./base64x-1.1.js"
import { RSAKey, parseBigInt } from "./../../js-bn/modules/rsa.js"
import { rng_get_bytes } from "./../../js-bn/modules/rng.js"
import { getChildIdx, getV, getVbyList, isASN1HEX, getTLVbyList } from "./asn1hex-1.1.js"
import { pemtohex } from "./base64x-1.1.js"
import { X509 } from "./x509-1.1.js"
import { BigInteger } from "./../../js-bn/modules/jsbn.js"
import { SecureRandom } from "./../../js-bn/modules/rng.js"
import { isString } from "./../../../include/type.js"

/**
 * PKCS#1 (OAEP) mask generation function
 * @param {Array<number>} seed 
 * @param {number} len 
 * @param {function(string):string} hash
 * @returns {string}
 */
function oaep_mgf1_arr(seed, len, hash) {
	var mask = '', i = 0;

	while (mask.length < len) {
		mask += hash(String.fromCharCode.apply(String, seed.concat([
			(i & 0xff000000) >> 24,
			(i & 0x00ff0000) >> 16,
			(i & 0x0000ff00) >> 8,
			i & 0x000000ff])));
		i += 1;
	}

	return mask;
}

/**
 * PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
 * @name oaep_pad
 * @param {string} s raw string of message
 * @param {number} n key length of RSA key
 * @param {(string | function(string):string)=} hash JavaScript function to calculate raw hash value from raw string or algorithm name (ex. "SHA1") 
 * @param {number=} hashLen byte length of resulted hash value (ex. 20 for SHA1)
 * @return {BigInteger} BigInteger object of resulted PKCS#1 OAEP padded message
 * @description
 * This function calculates OAEP padded message from original message.<br/>
 * NOTE: Since jsrsasign 6.2.0, 'hash' argument can accept an algorithm name such as "sha1".
 * @example
 * oaep_pad("aaa", 128) &rarr; big integer object // SHA-1 by default
 * oaep_pad("aaa", 128, function(s) {...}, 20);
 * oaep_pad("aaa", 128, "sha1");
 */
export function oaep_pad(s, n, hash, hashLen) {
	/** @type {function(string):string} */ let fnHash;

	if (!hash) hash = "sha1";

	if (typeof hash === "string") {
		let algName = MessageDigest.getCanonicalAlgName(hash);
		hashLen = MessageDigest.getHashLength(algName);
		fnHash = function (s) {
			return hextorstr(hashHex(rstrtohex(s), algName));
		};
	} else {
		fnHash = hash;
	}

	if (s.length + 2 * hashLen + 2 > n) {
		throw "Message too long for RSA";
	}

	let PS = '', i;

	for (i = 0; i < n - s.length - 2 * hashLen - 2; i += 1) {
		PS += '\x00';
	}

	let DB = fnHash('') + PS + '\x01' + s;
	let seed = new Array(hashLen);
	rng_get_bytes(seed);

	let dbMask = oaep_mgf1_arr(seed, DB.length, fnHash);
	let maskedDB = [];

	for (i = 0; i < DB.length; i += 1) {
		maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
	}

	let seedMask = oaep_mgf1_arr(maskedDB, seed.length, fnHash);
	let maskedSeed = [0];

	for (i = 0; i < seed.length; i += 1) {
		maskedSeed[i + 1] = seed[i] ^ seedMask.charCodeAt(i);
	}

	return new BigInteger(maskedSeed.concat(maskedDB));
}

/**
 * PKCS#1 (OAEP) mask generation function
 * @param {string} seed 
 * @param {number} len 
 * @param {function(string):string} hash 
 */
function oaep_mgf1_str(seed, len, hash) {
	let mask = '', i = 0;

	while (mask.length < len) {
		mask += hash(seed + String.fromCharCode.apply(String, [
			(i & 0xff000000) >> 24,
			(i & 0x00ff0000) >> 16,
			(i & 0x0000ff00) >> 8,
			i & 0x000000ff]));
		i += 1;
	}

	return mask;
}

/**
 * Undo PKCS#1 (OAEP) padding and, if valid, return the plaintext
 * @param {BigInteger} bnd BigInteger object of OAEP padded message
 * @param {number} n byte length of RSA key (i.e. 128 when RSA 1024bit)
 * @param {(string | function(string):string)=} hash JavaScript function to calculate raw hash value from raw string or algorithm name (ex. "SHA1") 
 * @param {number=} hashLen byte length of resulted hash value (i.e. 20 for SHA1)
 * @return {string} raw string of OAEP unpadded message
 * @description
 * This function do unpadding OAEP padded message then returns an original message.<br/>
 * NOTE: Since jsrsasign 6.2.0, 'hash' argument can accept an algorithm name such as "sha1".
 * @example
 * // DEFAULT(SHA1)
 * bi1 = oaep_pad("aaa", 128);
 * oaep_unpad(bi1, 128) &rarr; "aaa" // SHA-1 by default
 */
export function oaep_unpad(bnd, n, hash, hashLen) {
	/** @type {function(string):string} */ let fnHash;

	if (!hash) hash = "sha1";

	if (typeof hash === "string") {
		let algName = MessageDigest.getCanonicalAlgName(hash);
		hashLen = MessageDigest.getHashLength(algName);
		fnHash = function (s) {
			return hextorstr(hashHex(rstrtohex(s), algName));
		};
	} else {
		fnHash = hash;
		hashLen |= 0;
	}

	let ad = bnd.toByteArray();

	for (let i = 0; i < ad.length; i += 1) {
		ad[i] &= 0xff;
	}

	while (ad.length < n) {
		ad.unshift(0);
	}

	/** @type {string} */ let d = String.fromCharCode.apply(String, ad);

	if (d.length < 2 * hashLen + 2) {
		throw "Cipher too short";
	}

	let maskedSeed = d.substr(1, hashLen)
	let maskedDB = d.substr(hashLen + 1);

	let seedMask = oaep_mgf1_str(maskedDB, hashLen, fnHash);
	/** @type {Array<number>} */ let seed = [];

	for (let i = 0; i < maskedSeed.length; i += 1) {
		seed[i] = maskedSeed.charCodeAt(i) ^ seedMask.charCodeAt(i);
	}

	let dbMask = oaep_mgf1_str(String.fromCharCode.apply(String, seed),
		d.length - hashLen, fnHash);

	/** @type {Array<number>} */ let aDB = [];

	for (let i = 0; i < maskedDB.length; i += 1) {
		aDB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
	}

	/** @type {string} */ let DB = String.fromCharCode.apply(String, aDB);

	if (DB.substr(0, hashLen) !== fnHash('')) {
		throw "Hash mismatch";
	}

	DB = DB.substr(hashLen);

	let first_one = DB.indexOf('\x01');
	let last_zero = (first_one != -1) ? DB.substr(0, first_one).lastIndexOf('\x00') : -1;

	if (last_zero + 1 != first_one) {
		throw "Malformed data";
	}

	return DB.substr(first_one + 1);
}

let RE_HEXDECONLY = /[^0-9a-f]/gi

// ========================================================================
// Signature Generation
// ========================================================================

/**
 * @param {string} s 
 * @param {number} keySize 
 * @param {string} hashAlg 
 * @returns {string}
 */
function rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
	let hashFunc = function (s) { return hashString(s, hashAlg); };
	let sHashHex = hashFunc(s);

	return getPaddedDigestInfoHex(sHashHex, hashAlg, keySize);
}

/**
 * @param {string} hex 
 * @param {number} bitLength 
 * @returns {string}
 */
function zeroPaddingOfSignature(hex, bitLength) {
	let s = "";
	let nZero = bitLength / 4 - hex.length;
	for (let i = 0; i < nZero; i++) {
		s = s + "0";
	}
	return s + hex;
}

/**
 * PKCS#1 (PSS) mask generation function
 * @param {string} seed 
 * @param {number} len 
 * @param {function(string):string} hash 
 * @returns {string}
 */
function pss_mgf1_str(seed, len, hash) {
	let mask = '', i = 0;

	while (mask.length < len) {
		mask += hextorstr(hash(rstrtohex(seed + String.fromCharCode.apply(String, [
			(i & 0xff000000) >> 24,
			(i & 0x00ff0000) >> 16,
			(i & 0x0000ff00) >> 8,
			i & 0x000000ff]))));
		i += 1;
	}

	return mask;
}

// ========================================================================
// Signature Verification
// ========================================================================

/**
 * @param {BigInteger} biSig 
 * @param {string} hN 
 * @param {string} hE 
 * @returns {BigInteger}
 */
function rsasign_getDecryptSignatureBI(biSig, hN, hE) {
	let rsa = new RSAKeyEx();
	rsa.setPublic(hN, hE);
	let biDecryptedSig = rsa.doPublic(biSig);
	return biDecryptedSig;
}

/**
 * @param {BigInteger} biSig 
 * @param {string} hN 
 * @param {string} hE 
 * @returns {string}
 */
function rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
	let biDecryptedSig = rsasign_getDecryptSignatureBI(biSig, hN, hE);
	let hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
	return hDigestInfo;
}

/**
 * @param {string} hDigestInfo 
 * @returns {Array<string>}
 */
function rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
	for (let algName in DIGESTINFOHEAD) {
		let head = DIGESTINFOHEAD[algName];
		let len = head.length;
		if (hDigestInfo.substring(0, len) == head) {
			let a = [algName, hDigestInfo.substring(len)];
			return a;
		}
	}
	return [];
}

const SALT_LEN_HLEN = -1;
const SALT_LEN_MAX = -2;
const SALT_LEN_RECOVER = -2;

export class RSAKeyEx extends RSAKey {
	constructor() {
		super();

		/** @type {boolean} */ this.isPrivate;
		/** @type {boolean} */ this.isPublic;
		this.type = "RSA";
	}

	/**
	 * Set the public key fields N and e from hex strings
	 * @override
	 * @param {string | BigInteger} N 
	 * @param {string | number} E 
	 */
	setPublic(N, E) {
		this.isPublic = true;
		this.isPrivate = false;
		if (N instanceof BigInteger) {
			this.n = N;
			this.e = E | 0;
		} else if (isString(N) && isString(E)) {
			super.setPublic(/** @type {string} */ (N), /** @type {string} */ (E));
		} else
			throw "Invalid params";
	}

	/**
	 * Return the PKCS#1 OAEP RSA encryption of "text" as an even-length hex string
	 * @param {string} text 
	 * @param {(string | function(string):string)=} hash 
	 * @param {number=} hashLen 
	 */
	encryptOAEP(text, hash, hashLen) {
		let m = oaep_pad(text, (this.n.bitLength() + 7) >> 3, hash, hashLen);
		if (m == null) return null;
		let c = this.doPublic(m);
		if (c == null) return null;
		let h = c.toString(16);
		if ((h.length & 1) == 0) return h; else return "0" + h;
	}

	/**
	 * Set the private key fields N, e, and d from hex strings
	 * @override
	 * @param {string | BigInteger | null} N 
	 * @param {string | number | null} E 
	 * @param {string | BigInteger} D 
	 */
	setPrivate(N, E, D) {
		this.isPrivate = true;
		if (N instanceof BigInteger && D instanceof BigInteger) {
			this.n = N;
			this.e = E | 0;
			this.d = D;
		} else if (isString(N) && isString(E) && isString(D)) {
			super.setPrivate(/** @type {string} */ (N), /** @type {string} */ (E), /** @type {string} */ (D));
		} else
			throw "Invalid params";
	}

	/**
	 * Set the private key fields N, e, d and CRT params from hex strings
	 * @override
	 * @param {string} N 
	 * @param {string} E 
	 * @param {string} D 
	 * @param {string} P 
	 * @param {string} Q 
	 * @param {string} DP 
	 * @param {string} DQ 
	 * @param {string} C 
	 */
	setPrivateEx(N, E, D, P, Q, DP, DQ, C) {
		this.isPrivate = true;
		this.isPublic = false;
		if (N == null) throw "RSASetPrivateEx N == null";
		if (E == null) throw "RSASetPrivateEx E == null";
		if (N.length == 0) throw "RSASetPrivateEx N.length == 0";
		if (E.length == 0) throw "RSASetPrivateEx E.length == 0";

		super.setPrivateEx(N, E, D, P, Q, DP, DQ, C);
	}

	/**
	 * Generate a new random private key B bits long, using public expt E
	 * @override
	 * @param {number} B 
	 * @param {string} E 
	 */
	generate(B, E) {
		super.generate(B, E);
		this.isPrivate = true;
	}

	/**
	 * Return the PKCS#1 OAEP RSA decryption of "ctext".
	 * "ctext" is an even-length hex string and the output is a plain string.
	 * @param {string} ctext 
	 * @param {string | function(string):string} hash 
	 * @param {number=} hashLen 
	 */
	decryptOAEP(ctext, hash, hashLen) {
		let c = parseBigInt(ctext, 16);
		let m = this.doPrivate(c);
		if (m == null) return null;
		return oaep_unpad(m, (this.n.bitLength() + 7) >> 3, hash, hashLen);
	}

	/**
	 * static method to get array of field positions from hexadecimal PKCS#5 RSA private key.<br/>
	 * @param {string} hPrivateKey PEM PKCS#1/5 s private key string
	 * @return {Array<number>} array of field positions
	 * @example
	 * RSAKeyEx.getPosArrayOfChildrenFromHex("3082...") &rarr; [8, 32, ...]
	 */
	static getPosArrayOfChildrenFromHex(hPrivateKey) {
		return getChildIdx(hPrivateKey, 0);
	}

	/**
	 * static method to get array of hex field values from hexadecimal PKCS#5 RSA private key.<br/>
	 * @param {string} hPrivateKey PEM PKCS#1/5 s private key string
	 * @return {Array<string>} array of field hex value
	 * @example
	 * RSAKeyEx.getHexValueArrayOfChildrenFromHex("3082...") &rarr; ["00", "3b42...", ...]
	 */
	static getHexValueArrayOfChildrenFromHex(hPrivateKey) {
		let a = RSAKeyEx.getPosArrayOfChildrenFromHex(hPrivateKey);
		let h_v = getV(hPrivateKey, a[0]);
		let h_n = getV(hPrivateKey, a[1]);
		let h_e = getV(hPrivateKey, a[2]);
		let h_d = getV(hPrivateKey, a[3]);
		let h_p = getV(hPrivateKey, a[4]);
		let h_q = getV(hPrivateKey, a[5]);
		let h_dp = getV(hPrivateKey, a[6]);
		let h_dq = getV(hPrivateKey, a[7]);
		let h_co = getV(hPrivateKey, a[8]);
		/** @type {Array<string>} */ let res = new Array();
		res.push(h_v, h_n, h_e, h_d, h_p, h_q, h_dp, h_dq, h_co);
		return res;
	}

	/**
	 * read PKCS#1 private key from a string<br/>
	 * @param {string} keyPEM string of PKCS#1 private key.
	 */
	readPrivateKeyFromPEMString(keyPEM) {
		let keyHex = pemtohex(keyPEM);
		let a = RSAKeyEx.getHexValueArrayOfChildrenFromHex(keyHex);
		this.setPrivateEx(a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	}

	/**
	 * read an ASN.1 hexadecimal string of PKCS#1/5 plain RSA private key<br/>
	 * @param {string} h hexadecimal string of PKCS#1/5 plain RSA private key
	 */
	readPKCS5PrvKeyHex(h) {
		let a = RSAKeyEx.getHexValueArrayOfChildrenFromHex(h);
		this.setPrivateEx(a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	}

	/**
	 * read an ASN.1 hexadecimal string of PKCS#8 plain RSA private key<br/>
	 * @param {string} h hexadecimal string of PKCS#8 plain RSA private key
	 */
	readPKCS8PrvKeyHex(h) {
		/** @type {string} */ let hN;
		/** @type {string} */ let hE;
		/** @type {string} */ let hD;
		/** @type {string} */ let hP;
		/** @type {string} */ let hQ;
		/** @type {string} */ let hDP;
		/** @type {string} */ let hDQ;
		/** @type {string} */ let hCO;

		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		try {
			hN = getVbyList(h, 0, [2, 0, 1], "02");
			hE = getVbyList(h, 0, [2, 0, 2], "02");
			hD = getVbyList(h, 0, [2, 0, 3], "02");
			hP = getVbyList(h, 0, [2, 0, 4], "02");
			hQ = getVbyList(h, 0, [2, 0, 5], "02");
			hDP = getVbyList(h, 0, [2, 0, 6], "02");
			hDQ = getVbyList(h, 0, [2, 0, 7], "02");
			hCO = getVbyList(h, 0, [2, 0, 8], "02");
		} catch (ex) {
			throw "malformed PKCS#8 plain RSA private key";
		}

		this.setPrivateEx(hN, hE, hD, hP, hQ, hDP, hDQ, hCO);
	}

	/**
	 * read an ASN.1 hexadecimal string of PKCS#5 RSA public key<br/>
	 * @param {string} h hexadecimal string of PKCS#5 public key
	 */
	readPKCS5PubKeyHex(h) {
		if (isASN1HEX(h) === false)
			throw "keyHex is not ASN.1 hex string";
		let aIdx = getChildIdx(h, 0);
		if (aIdx.length !== 2 ||
			h.substr(aIdx[0], 2) !== "02" ||
			h.substr(aIdx[1], 2) !== "02")
			throw "wrong hex for PKCS#5 public key";
		let hN = getV(h, aIdx[0]);
		let hE = getV(h, aIdx[1]);
		this.setPublic(hN, hE);
	}

	/**
	 * read an ASN.1 hexadecimal string of PKCS#8 RSA public key<br/>
	 * @param {string} h hexadecimal string of PKCS#8 public key
	 */
	readPKCS8PubKeyHex(h) {
		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		// 06092a864886f70d010101: OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
		if (getTLVbyList(h, 0, [0, 0]) !== "06092a864886f70d010101")
			throw "not PKCS8 RSA public key";

		let p5hex = getTLVbyList(h, 0, [1, 0]);
		this.readPKCS5PubKeyHex(p5hex);
	}

	/**
	 * read an ASN.1 hexadecimal string of X.509 RSA public key certificate<br/>
	 * @param {string} h hexadecimal string of X.509 RSA public key certificate
	 * @param {number} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
	 */
	readCertPubKeyHex(h, nthPKI) {
		let x = new X509();
		x.readCertHex(h);
		let hPub = x.getPublicKeyHex();
		if (hPub !== null)
			this.readPKCS8PubKeyHex(hPub);
	}

	/**
	 * sign for a message string with RSA private key.<br/>
	 * @param {string} s message string to be signed.
	 * @param {string} hashAlg hash algorithm name for signing.<br/>
	 * @return {string} hexadecimal string of signature value.
	 */
	sign(s, hashAlg) {
		let sHashHex = hashString(s, hashAlg);

		return this.signWithMessageHash(sHashHex, hashAlg);
	}

	/**
	 * sign hash value of message to be signed with RSA private key.<br/>
	 * @param {string} sHashHex hexadecimal string of hash value of message to be signed.
	 * @param {string} hashAlg hash algorithm name for signing.<br/>
	 * @return {string} hexadecimal string of signature value.
	 */
	signWithMessageHash(sHashHex, hashAlg) {
		let hPM = getPaddedDigestInfoHex(sHashHex, hashAlg, this.n.bitLength());
		let biPaddedMessage = parseBigInt(hPM, 16);
		let biSign = this.doPrivate(biPaddedMessage);
		let hexSign = biSign.toString(16);
		return zeroPaddingOfSignature(hexSign, this.n.bitLength());
	}

	/**
	 * sign for a message string with RSA private key by PKCS#1 PSS signing.<br/>
	 * @param {string} s message string to be signed.
	 * @param {string} hashAlg hash algorithm name for signing.
	 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
	 *        There are two special values:
	 *        <ul>
	 *        <li>-1: sets the salt length to the digest length</li>
	 *        <li>-2: sets the salt length to maximum permissible value
	 *           (i.e. keybytelen - hashbytelen - 2)</li>
	 *        </ul>
	 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
	 * @return {string} hexadecimal string of signature value.
	 */
	signPSS(s, hashAlg, sLen) {
		let hHash = hashHex(rstrtohex(s), hashAlg);

		if (sLen === undefined) sLen = -1;
		return this.signWithMessageHashPSS(hHash, hashAlg, sLen);
	}

	/**
	 * sign hash value of message with RSA private key by PKCS#1 PSS signing.<br/>
	 * @param {string} hHash hexadecimal hash value of message to be signed.
	 * @param {string} hashAlg hash algorithm name for signing.
	 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
	 *        There are two special values:
	 *        <ul>
	 *        <li>-1: sets the salt length to the digest length</li>
	 *        <li>-2: sets the salt length to maximum permissible value
	 *           (i.e. keybytelen - hashbytelen - 2)</li>
	 *        </ul>
	 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
	 * @return {string} hexadecimal string of signature value.
	 */
	signWithMessageHashPSS(hHash, hashAlg, sLen) {
		let mHash = hextorstr(hHash);
		let hLen = mHash.length;
		let emBits = this.n.bitLength() - 1;
		let emLen = Math.ceil(emBits / 8);
		/** @type {number} */ let i;
		let hashFunc = function (sHex) { return hashHex(sHex, hashAlg); }

		if (sLen === -1 || sLen === undefined) {
			sLen = hLen; // same as hash length
		} else if (sLen === -2) {
			sLen = emLen - hLen - 2; // maximum
		} else if (sLen < -2) {
			throw "invalid salt length";
		}

		if (emLen < (hLen + sLen + 2)) {
			throw "data too long";
		}

		let salt = '';

		if (sLen > 0) {
			salt = new Array(sLen);
			new SecureRandom().nextBytes(salt);
			salt = String.fromCharCode.apply(String, salt);
		}

		let H = hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt)));
		/** @type {Array<number>} */ let PS = [];

		for (i = 0; i < emLen - sLen - hLen - 2; i += 1) {
			PS[i] = 0x00;
		}

		let DB = String.fromCharCode.apply(String, PS) + '\x01' + salt;
		let dbMask = pss_mgf1_str(H, DB.length, hashFunc);
		/** @type {Array<number>} */ let maskedDB = [];

		for (i = 0; i < DB.length; i += 1) {
			maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
		}

		let mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
		maskedDB[0] &= ~mask;

		for (i = 0; i < hLen; i++) {
			maskedDB.push(H.charCodeAt(i));
		}

		maskedDB.push(0xbc);

		return zeroPaddingOfSignature(this.doPrivate(new BigInteger(maskedDB)).toString(16),
			this.n.bitLength());
	}

	/**
	 * verifies a sigature for a message string with RSA public key.<br/>
	 * @param {string} sMsg message string to be verified.
	 * @param {string} hSig hexadecimal string of siganture.<br/>
	 *                 non-hexadecimal charactors including new lines will be ignored.
	 * @return {boolean} returns true if valid, otherwise false
	 */
	verify(sMsg, hSig) {
		hSig = hSig.replace(RE_HEXDECONLY, '');
		hSig = hSig.replace(/[ \n]+/g, "");
		let biSig = parseBigInt(hSig, 16);
		if (biSig.bitLength() > this.n.bitLength()) return false;
		let biDecryptedSig = this.doPublic(biSig);
		let hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
		let digestInfoAry = rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

		if (digestInfoAry.length == 0) return false;
		let algName = digestInfoAry[0];
		let diHashValue = digestInfoAry[1];
		let msgHashValue = hashString(sMsg, algName);
		return (diHashValue == msgHashValue);
	}

	/**
	 * verifies a sigature for a message string with RSA public key.<br/>
	 * @param {string} sHashHex hexadecimal hash value of message to be verified.
	 * @param {string} hSig hexadecimal string of siganture.<br/>
	 *                 non-hexadecimal charactors including new lines will be ignored.
	 * @return {boolean} returns true if valid, otherwise false
	 */
	verifyWithMessageHash(sHashHex, hSig) {
		hSig = hSig.replace(RE_HEXDECONLY, '');
		hSig = hSig.replace(/[ \n]+/g, "");
		let biSig = parseBigInt(hSig, 16);
		if (biSig.bitLength() > this.n.bitLength()) return false;
		let biDecryptedSig = this.doPublic(biSig);
		let hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
		let digestInfoAry = rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

		if (digestInfoAry.length == 0) return false;
		let algName = digestInfoAry[0];
		let diHashValue = digestInfoAry[1];
		return (diHashValue == sHashHex);
	}

	/**
	 * verifies a sigature for a message string with RSA public key by PKCS#1 PSS sign.<br/>
	 * @param {string} sMsg message string to be verified.
	 * @param {string} hSig hexadecimal string of signature value
	 * @param {string} hashAlg hash algorithm name
	 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
	 *        There are two special values:
	 *        <ul>
	 *        <li>-1: sets the salt length to the digest length</li>
	 *        <li>-2: sets the salt length to maximum permissible value
	 *           (i.e. keybytelen - hashbytelen - 2)</li>
	 *        </ul>
	 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
	 * @return {boolean} returns true if valid, otherwise false
	 */
	verifyPSS(sMsg, hSig, hashAlg, sLen) {
		let hHash = hashHex(rstrtohex(sMsg), hashAlg);

		if (sLen === undefined) sLen = -1;
		return this.verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen);
	}

	/**
	 * verifies a sigature for a hash value of message string with RSA public key by PKCS#1 PSS sign.<br/>
	 * @param {string} hHash hexadecimal hash value of message string to be verified.
	 * @param {string} hSig hexadecimal string of signature value
	 * @param {string} hashAlg hash algorithm name
	 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
	 *        There are two special values:
	 *        <ul>
	 *        <li>-1: sets the salt length to the digest length</li>
	 *        <li>-2: sets the salt length to maximum permissible value
	 *           (i.e. keybytelen - hashbytelen - 2)</li>
	 *        </ul>
	 *        DEFAULT is -1 (NOTE: OpenSSL's default is -2.)
	 * @return {boolean} returns true if valid, otherwise false
	 */
	verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen) {
		let biSig = new BigInteger(hSig, 16);

		if (biSig.bitLength() > this.n.bitLength()) {
			return false;
		}

		let hashFunc = function (sHex) { return hashHex(sHex, hashAlg); };
		let mHash = hextorstr(hHash);
		let hLen = mHash.length;
		let emBits = this.n.bitLength() - 1;
		let emLen = Math.ceil(emBits / 8);
		/** @type {number} */ let i;

		if (sLen === -1 || sLen === undefined) {
			sLen = hLen; // same as hash length
		} else if (sLen === -2) {
			sLen = emLen - hLen - 2; // recover
		} else if (sLen < -2) {
			throw "invalid salt length";
		}

		if (emLen < (hLen + sLen + 2)) {
			throw "data too long";
		}

		let em = this.doPublic(biSig).toByteArray();

		for (i = 0; i < em.length; i += 1) {
			em[i] &= 0xff;
		}

		while (em.length < emLen) {
			em.unshift(0);
		}

		if (em[emLen - 1] !== 0xbc) {
			throw "encoded message does not end in 0xbc";
		}

		/** @type {string} */ let sem = String.fromCharCode.apply(String, em);

		let maskedDB = sem.substr(0, emLen - hLen - 1);
		let H = sem.substr(maskedDB.length, hLen);

		let mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;

		if ((maskedDB.charCodeAt(0) & mask) !== 0) {
			throw "bits beyond keysize not zero";
		}

		let dbMask = pss_mgf1_str(H, maskedDB.length, hashFunc);
		/** @type {Array<number>} */ let DB = [];

		for (i = 0; i < maskedDB.length; i += 1) {
			DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
		}

		DB[0] &= ~mask;

		let checkLen = emLen - hLen - sLen - 2;

		for (i = 0; i < checkLen; i += 1) {
			if (DB[i] !== 0x00) {
				throw "leftmost octets not zero";
			}
		}

		if (DB[checkLen] !== 0x01) {
			throw "0x01 marker not found";
		}

		return H === hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash +
			String.fromCharCode.apply(String, DB.slice(-sLen)))));
	}
}
