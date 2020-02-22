/*
 * Original work Copyright (c) ? Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 */

"use strict";

import { MessageDigest, hashHex } from "./crypto-1.1.js"
import { rstrtohex, hextorstr } from "./base64x-1.1.js"
import { RSAKey, parseBigInt } from "./../../js-bn/modules/rsa.js"
import { rng_get_bytes } from "./../../js-bn/modules/rng.js"

/**
 * PKCS#1 (OAEP) mask generation function
 * @param {string} seed 
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
	let algName = null;

	/** @type {function(string):string} */ let fnHash;

	if (!hash) hash = "sha1";

	if (typeof hash === "string") {
		algName = MessageDigest.getCanonicalAlgName(hash);
		hashLen = MessageDigest.getHashLength(algName);
		fnHash = function (s) {
			return hextorstr(hashHex(rstrtohex(s), algName));
		};
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
 * @param {BigInteger} d BigInteger object of OAEP padded message
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
export function oaep_unpad(d, n, hash, hashLen) {
	let algName = null;

	/** @type {function(string):string} */ let fnHash;

	if (!hash) hash = "sha1";

	if (typeof hash === "string") {
		algName = MessageDigest.getCanonicalAlgName(hash);
		hashLen = MessageDigest.getHashLength(algName);
		fnHash = function (s) {
			return hextorstr(hashHex(rstrtohex(s), algName));
		};
	}

	d = d.toByteArray();

	for (let i = 0; i < d.length; i += 1) {
		d[i] &= 0xff;
	}

	while (d.length < n) {
		d.unshift(0);
	}

	d = String.fromCharCode.apply(String, d);

	if (d.length < 2 * hashLen + 2) {
		throw "Cipher too short";
	}

	let maskedSeed = d.substr(1, hashLen)
	let maskedDB = d.substr(hashLen + 1);

	let seedMask = oaep_mgf1_str(maskedDB, hashLen, fnHash);
	let seed = [];

	for (let i = 0; i < maskedSeed.length; i += 1) {
		seed[i] = maskedSeed.charCodeAt(i) ^ seedMask.charCodeAt(i);
	}

	let dbMask = oaep_mgf1_str(String.fromCharCode.apply(String, seed),
		d.length - hashLen, fnHash);

	let DB = [];

	for (let i = 0; i < maskedDB.length; i += 1) {
		DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
	}

	DB = String.fromCharCode.apply(String, DB);

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
		} else
			super.setPublic(N, E);
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
		}
		else
			super.setPrivate(N, E, D);
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
	 * @param {*} hash 
	 * @param {*} hashLen 
	 */
	decryptOAEP(ctext, hash, hashLen) {
		let c = parseBigInt(ctext, 16);
		let m = this.doPrivate(c);
		if (m == null) return null;
		return oaep_unpad(m, (this.n.bitLength() + 7) >> 3, hash, hashLen);
	}
}
