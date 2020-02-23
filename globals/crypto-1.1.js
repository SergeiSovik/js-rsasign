/*
 * crypto.js - Cryptographic Algorithm Provider class
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

"use strict";

import { Hasher } from "./../../js-crypto/modules/hasher.js"
import { HasherRIPEMD160 } from "./../../js-crypto/modules/ripemd160.js"
import { HasherMD5 } from "./../../js-crypto/modules/md5.js"
import { HasherSHA1 } from "./../../js-crypto/modules/sha1.js"
import { HasherSHA224 } from "./../../js-crypto/modules/sha224.js"
import { HasherSHA256 } from "./../../js-crypto/modules/sha256.js"
import { HasherSHA384 } from "./../../js-crypto/modules/sha384.js"
import { HasherSHA512 } from "./../../js-crypto/modules/sha512.js"
import { Hex } from "./../../js-crypto/modules/enc-hex.js"
import { rng_get_bytes } from "./../../js-bn/modules/rng.js"
import { HMAC } from "./../../js-crypto/modules/hmac.js"
import { WordArray } from "./../../js-crypto/modules/wordarray.js"

/**
 * Cryptographic algorithm provider library module
 * <p>
 * This module privides following crytpgrahic classes.
 * <ul>
 * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
 * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
 * <li>{@link KJUR.crypto.Cipher} - class for encrypting and decrypting data</li>
 * <li>{@link Util} - cryptographic utility functions and properties</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 */

/**
 * PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
 * @type {Object<string, string>}
 */
export const DIGESTINFOHEAD = {
	'sha1': "3021300906052b0e03021a05000414",
	'sha224': "302d300d06096086480165030402040500041c",
	'sha256': "3031300d060960864801650304020105000420",
	'sha384': "3041300d060960864801650304020205000430",
	'sha512': "3051300d060960864801650304020305000440",
	'md2': "3020300c06082a864886f70d020205000410",
	'md5': "3020300c06082a864886f70d020505000410",
	'ripemd160': "3021300906052b2403020105000414",
};

/**
 * Associative array of default provider name for each hash and signature algorithms
 * @type {Object<string, string>}
 */
export const DEFAULTPROVIDER = {
	'md5': 'cryptojs',
	'sha1': 'cryptojs',
	'sha224': 'cryptojs',
	'sha256': 'cryptojs',
	'sha384': 'cryptojs',
	'sha512': 'cryptojs',
	'ripemd160': 'cryptojs',
	'hmacmd5': 'cryptojs',
	'hmacsha1': 'cryptojs',
	'hmacsha224': 'cryptojs',
	'hmacsha256': 'cryptojs',
	'hmacsha384': 'cryptojs',
	'hmacsha512': 'cryptojs',
	'hmacripemd160': 'cryptojs',

	'MD5withRSA': 'cryptojs/jsrsa',
	'SHA1withRSA': 'cryptojs/jsrsa',
	'SHA224withRSA': 'cryptojs/jsrsa',
	'SHA256withRSA': 'cryptojs/jsrsa',
	'SHA384withRSA': 'cryptojs/jsrsa',
	'SHA512withRSA': 'cryptojs/jsrsa',
	'RIPEMD160withRSA': 'cryptojs/jsrsa',

	'MD5withECDSA': 'cryptojs/jsrsa',
	'SHA1withECDSA': 'cryptojs/jsrsa',
	'SHA224withECDSA': 'cryptojs/jsrsa',
	'SHA256withECDSA': 'cryptojs/jsrsa',
	'SHA384withECDSA': 'cryptojs/jsrsa',
	'SHA512withECDSA': 'cryptojs/jsrsa',
	'RIPEMD160withECDSA': 'cryptojs/jsrsa',

	'SHA1withDSA': 'cryptojs/jsrsa',
	'SHA224withDSA': 'cryptojs/jsrsa',
	'SHA256withDSA': 'cryptojs/jsrsa',

	'MD5withRSAandMGF1': 'cryptojs/jsrsa',
	'SHA1withRSAandMGF1': 'cryptojs/jsrsa',
	'SHA224withRSAandMGF1': 'cryptojs/jsrsa',
	'SHA256withRSAandMGF1': 'cryptojs/jsrsa',
	'SHA384withRSAandMGF1': 'cryptojs/jsrsa',
	'SHA512withRSAandMGF1': 'cryptojs/jsrsa',
	'RIPEMD160withRSAandMGF1': 'cryptojs/jsrsa',
};

/**
 * @type {Object<string, Hasher>}
 */
const CRYPTOJSMESSAGEDIGESTNAME = {
	'md5': HasherMD5,
	'sha1': HasherSHA1,
	'sha224': HasherSHA224,
	'sha256': HasherSHA256,
	'sha384': HasherSHA384,
	'sha512': HasherSHA512,
	'ripemd160': HasherRIPEMD160
};

/**
 * get hexadecimal DigestInfo
 * @param {string} hHash hexadecimal hash value
 * @param {string} alg hash algorithm name (ex. 'sha1')
 * @return {string} hexadecimal string DigestInfo ASN.1 structure
 */
export function getDigestInfoHex(hHash, alg) {
	if (typeof DIGESTINFOHEAD[alg] == "undefined")
		throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return DIGESTINFOHEAD[alg] + hHash;
}

/**
 * get PKCS#1 padded hexadecimal DigestInfo
 * @param {string} hHash hexadecimal hash value of message to be signed
 * @param {string} alg hash algorithm name (ex. 'sha1')
 * @param {number} keySize key bit length (ex. 1024)
 * @return {string} hexadecimal string of PKCS#1 padded DigestInfo
 */
export function getPaddedDigestInfoHex(hHash, alg, keySize) {
	let hDigestInfo = getDigestInfoHex(hHash, alg);
	let pmStrLen = keySize / 4; // minimum PM length

	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
		throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

	let hHead = "0001";
	let hTail = "00" + hDigestInfo;
	let hMid = "";
	let fLen = pmStrLen - hHead.length - hTail.length;
	for (let i = 0; i < fLen; i += 2) {
		hMid += "ff";
	}
	let hPaddedMessage = hHead + hMid + hTail;
	return hPaddedMessage;
}

/**
 * get hexadecimal hash of string with specified algorithm
 * @param {string} s input string to be hashed
 * @param {string} alg hash algorithm name
 * @return {string} hexadecimal string of hash value
 */
export function hashString(s, alg) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': alg });
	return md.digestString(s);
}

/**
 * get hexadecimal hash of hexadecimal string with specified algorithm
 * @param {string} sHex input hexadecimal string to be hashed
 * @param {string} alg hash algorithm name
 * @return {string} hexadecimal string of hash value
 */
export function hashHex(sHex, alg) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': alg });
	return md.digestHex(sHex);
}

/**
 * get hexadecimal SHA1 hash of string
 * @param {string} s input string to be hashed
 * @return {string} hexadecimal string of hash value
 */
export function sha1(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'sha1', 'prov': 'cryptojs' });
	return md.digestString(s);
}

/**
 * get hexadecimal SHA256 hash of string
 * @param {string} s input string to be hashed
 * @return {string} hexadecimal string of hash value
 */
export function sha256(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'sha256', 'prov': 'cryptojs' });
	return md.digestString(s);
}

export function sha256Hex(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'sha256', 'prov': 'cryptojs' });
	return md.digestHex(s);
}

/**
 * get hexadecimal SHA512 hash of string
 * @param {string} s input string to be hashed
 * @return {string} hexadecimal string of hash value
 */
export function sha512(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'sha512', 'prov': 'cryptojs' });
	return md.digestString(s);
}

export function sha512Hex(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'sha512', 'prov': 'cryptojs' });
	return md.digestHex(s);
}

/**
 * get hexadecimal MD5 hash of string
 * @param {string} s input string to be hashed
 * @return {string} hexadecimal string of hash value
 * @example
 * md5('aaa') &rarr; 47bce5c74f589f4867dbd57e9ca9f808
 */
export function md5(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'md5', 'prov': 'cryptojs' });
	return md.digestString(s);
}

/**
 * get hexadecimal RIPEMD160 hash of string
 * @param {string} s input string to be hashed
 * @return {string} hexadecimal string of hash value
 * @example
 * ripemd160("aaa") &rarr; 08889bd7b151aa174c21f33f59147fa65381edea
 */
export function ripemd160(s) {
	let md = new KJUR.crypto.MessageDigest({ 'alg': 'ripemd160', 'prov': 'cryptojs' });
	return md.digestString(s);
}

/**
 * get hexadecimal string of random value from with specified byte length<br/>
 * @param {number} n length of bytes of random
 * @return {string} hexadecimal string of random
 * @example
 * getRandomHexOfNbytes(3) &rarr; "6314af", "000000" or "001fb4"
 * getRandomHexOfNbytes(128) &rarr; "8fbc..." in 1024bits 
 */
export function getRandomHexOfNbytes(n) {
	let ba = new Array(n);
	rng_get_bytes(ba);
	return BAtohex(ba);
}

/**
 * get BigInteger object of random value from with specified byte length<br/>
 * @param {number} n length of bytes of random
 * @return {BigInteger} BigInteger object of specified random value
 * @example
 * getRandomBigIntegerOfNbytes(3) &rarr; 6314af of BigInteger
 * getRandomBigIntegerOfNbytes(128) &rarr; 8fbc... of BigInteger
 */
export function getRandomBigIntegerOfNbytes(n) {
	return new BigInteger(getRandomHexOfNbytes(n), 16);
}

/**
 * get hexadecimal string of random value from with specified bit length<br/>
 * @param {number} n length of bits of random
 * @return {string} hexadecimal string of random
 * @example
 * getRandomHexOfNbits(24) &rarr; "6314af", "000000" or "001fb4"
 * getRandomHexOfNbits(1024) &rarr; "8fbc..." in 1024bits 
 */
export function getRandomHexOfNbits(n) {
	let n_remainder = n % 8;
	let n_quotient = (n - n_remainder) / 8;
	let ba = new Array(n_quotient + 1);
	rng_get_bytes(ba);
	ba[0] = (((255 << n_remainder) & 255) ^ 255) & ba[0];
	return BAtohex(ba);
}

/**
 * get BigInteger object of random value from with specified bit length<br/>
 * @param {number} n length of bits of random
 * @return {BigInteger} BigInteger object of specified random value
 * @example
 * getRandomBigIntegerOfNbits(24) &rarr; 6314af of BigInteger
 * getRandomBigIntegerOfNbits(1024) &rarr; 8fbc... of BigInteger
 */
export function getRandomBigIntegerOfNbits(n) {
	return new BigInteger(getRandomHexOfNbits(n), 16);
}

/**
 * get BigInteger object of random value from zero to max value<br/>
 * @param {BigInteger} biMax max value of BigInteger object for random value
 * @return {BigInteger} BigInteger object of specified random value
 * @description
 * This static method generates a BigInteger object with random value
 * greater than or equal to zero and smaller than or equal to biMax
 * (i.e. 0 &le; result &le; biMax).
 * @example
 * biMax = new BigInteger("3fa411...", 16);
 * getRandomBigIntegerZeroToMax(biMax) &rarr; 8fbc... of BigInteger
 */
export function getRandomBigIntegerZeroToMax(biMax) {
	let bitLenMax = biMax.bitLength();
	while (1) {
		let biRand = getRandomBigIntegerOfNbits(bitLenMax);
		if (biMax.compareTo(biRand) != -1) return biRand;
	}
}

/**
 * get BigInteger object of random value from min value to max value<br/>
 * @param {BigInteger} biMin min value of BigInteger object for random value
 * @param {BigInteger} biMax max value of BigInteger object for random value
 * @return {BigInteger} BigInteger object of specified random value
 * @description
 * This static method generates a BigInteger object with random value
 * greater than or equal to biMin and smaller than or equal to biMax
 * (i.e. biMin &le; result &le; biMax).
 * @example
 * biMin = new BigInteger("2fa411...", 16);
 * biMax = new BigInteger("3fa411...", 16);
 * getRandomBigIntegerMinToMax(biMin, biMax) &rarr; 32f1... of BigInteger
 */
export function getRandomBigIntegerMinToMax(biMin, biMax) {
	let flagCompare = biMin.compareTo(biMax);
	if (flagCompare == 1) throw "biMin is greater than biMax";
	if (flagCompare == 0) return biMin;

	let biDiff = biMax.subtract(biMin);
	let biRand = getRandomBigIntegerZeroToMax(biDiff);
	return biRand.add(biMin);
}

// === Mac ===============================================================

export const HASHLENGTH = {
	'md5': 16,
	'sha1': 20,
	'sha224': 28,
	'sha256': 32,
	'sha384': 48,
	'sha512': 64,
	'ripemd160': 20
};

/**
 * MessageDigest class which is very similar to java.security.MessageDigest class<br/>
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>md5 - cryptojs</li>
 * <li>sha1 - cryptojs</li>
 * <li>sha224 - cryptojs</li>
 * <li>sha256 - cryptojs</li>
 * <li>sha384 - cryptojs</li>
 * <li>sha512 - cryptojs</li>
 * <li>ripemd160 - cryptojs</li>
 * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
 * </ul>
 * @example
 * // CryptoJS provider sample
 * let md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
 * md.updateString('aaa')
 * let mdHex = md.digest()
 *
 * // SJCL(Stanford JavaScript Crypto Library) provider sample
 * let md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
 * md.updateString('aaa')
 * let mdHex = md.digest()
 *
 * // HASHLENGTH property
 * HASHLENGTH['sha1'] &rarr 20
 * HASHLENGTH['sha512'] &rarr 64
 */
export class MessageDigest {
	/**
	 * @param {Object<string, string>=} params 
	 */
	constructor(params) {
		/** @type {Hasher | null} */ this.md = null;
		/** @type {string | null} */ this.algName = null;
		/** @type {string | null} */ this.provName = null;

		if (params !== undefined) {
			if (params['alg'] !== undefined) {
				this.algName = params['alg'];
				if (params['prov'] === undefined)
					this.provName = DEFAULTPROVIDER[this.algName];
				this.setAlgAndProvider(this.algName, this.provName);
			}
		}
	}

	/**
	 * get canonical hash algorithm name<br/>
	 * @param {string} alg hash algorithm name (ex. MD5, SHA-1, SHA1, SHA512 et.al.)
	 * @return {string} canonical hash algorithm name
	 * @description
	 * This static method normalizes from any hash algorithm name such as
	 * "SHA-1", "SHA1", "MD5", "sha512" to lower case name without hyphens
	 * such as "sha1".
	 * @example
	 * MessageDigest.getCanonicalAlgName("SHA-1") &rarr "sha1"
	 * MessageDigest.getCanonicalAlgName("MD5")   &rarr "md5"
	 */
	static getCanonicalAlgName(alg) {
		if (typeof alg === "string") {
			alg = alg.toLowerCase();
			alg = alg.replace(/-/, '');
		}
		return alg;
	}

	/**
	 * get resulted hash byte length for specified algorithm name<br/>
	 * @param {string} alg non-canonicalized hash algorithm name (ex. MD5, SHA-1, SHA1, SHA512 et.al.)
	 * @return {number} resulted hash byte length
	 * @description
	 * This static method returns resulted byte length for specified algorithm name such as "SHA-1".
	 * @example
	 * MessageDigest.getHashLength("SHA-1") &rarr 20
	 * MessageDigest.getHashLength("sha1") &rarr 20
	 */
	static getHashLength(alg) {
		let MD = KJUR.crypto.MessageDigest
		let alg2 = MD.getCanonicalAlgName(alg);
		if (MD.HASHLENGTH[alg2] === undefined)
			throw "not supported algorithm: " + alg;
		return MD.HASHLENGTH[alg2];
	}

	/**
     * set hash algorithm and provider<br/>
     * @param {string} alg hash algorithm name
     * @param {string} prov provider name
     * @description
     * This methods set an algorithm and a cryptographic provider.<br/>
     * Here is acceptable algorithm names ignoring cases and hyphens:
     * <ul>
     * <li>MD5</li>
     * <li>SHA1</li>
     * <li>SHA224</li>
     * <li>SHA256</li>
     * <li>SHA384</li>
     * <li>SHA512</li>
     * <li>RIPEMD160</li>
     * </ul>
     * NOTE: Since jsrsasign 6.2.0 crypto 1.1.10, this method ignores
     * upper or lower cases. Also any hyphens (i.e. "-") will be ignored
     * so that "SHA1" or "SHA-1" will be acceptable.
     * @example
     * // for SHA1
     * md.setAlgAndProvider('sha1', 'cryptojs');
     * md.setAlgAndProvider('SHA1');
     * // for RIPEMD160
     * md.setAlgAndProvider('ripemd160', 'cryptojs');
     */
	setAlgAndProvider(alg, prov) {
		alg = MessageDigest.getCanonicalAlgName(alg);

		if (alg !== null && prov === undefined) prov = DEFAULTPROVIDER[alg];

		// for cryptojs
		if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 && prov == 'cryptojs') {
			try {
				this.md = new CRYPTOJSMESSAGEDIGESTNAME[alg]();
			} catch (ex) {
				throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
			}
		}
	}

	/**
     * update digest by specified string
     * @param {string} str string to update
     * @description
     * @example
     * md.updateString('New York');
	 */
	updateString(str) {
		if (this.md === null)
			throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
		this.md.update(str);
	}

	/**
     * update digest by specified hexadecimal string
     * @param {string} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
	 */
	updateHex(hex) {
		if (this.md === null)
			throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
		let wHex = Hex.parse(hex);
		this.md.update(wHex);
	}

    /**
     * completes hash calculation and returns hash result
     * @description
     * @example
     * md.digest()
     */
	digest() {
		if (this.md === null)
			throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
		let hash = this.md.finalize();
		return hash.toString(Hex);
	}

	/**
     * performs final update on the digest using string, then completes the digest computation
     * @param {string} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
	 */
	digestString(str) {
		if (this.md === null)
			throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
		this.updateString(str);
		return this.digest();
	}

	/**
     * performs final update on the digest using hexadecimal string, then completes the digest computation
     * @param {string} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
	 */
	digestHex(hex) {
		if (this.md === null)
			throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
		this.updateHex(hex);
		return this.digest();
	}
}

// === Mac ===============================================================

/**
 * Mac(Message Authentication Code) class which is very similar to java.security.Mac class  * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>hmacmd5 - cryptojs</li>
 * <li>hmacsha1 - cryptojs</li>
 * <li>hmacsha224 - cryptojs</li>
 * <li>hmacsha256 - cryptojs</li>
 * <li>hmacsha384 - cryptojs</li>
 * <li>hmacsha512 - cryptojs</li>
 * </ul>
 * NOTE: HmacSHA224 and HmacSHA384 issue was fixed since jsrsasign 4.1.4.
 * Please use 'ext/cryptojs-312-core-fix*.js' instead of 'core.js' of original CryptoJS
 * to avoid those issue.
 * <br/>
 * NOTE2: Hmac signature bug was fixed in jsrsasign 4.9.0 by providing CryptoJS
 * bug workaround.
 * <br/>
 * Please see {@link KJUR.crypto.Mac.setPassword}, how to provide password
 * in various ways in detail.
 * @example
 * let mac = new KJUR.crypto.Mac({alg: "HmacSHA1", "pass": "pass"});
 * mac.updateString('aaa')
 * let macHex = mac.doFinal()
 *
 * // other password representation 
 * let mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"hex":  "6161"}});
 * let mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"utf8": "aa"}});
 * let mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"rstr": "\x61\x61"}});
 * let mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64":  "Mi02/+...a=="}});
 * let mac = new KJUR.crypto.Mac({alg: "HmacSHA256", "pass": {"b64u": "Mi02_-...a"}});
 */
export class Mac {
	constructor(params) {
		/** @type {HMAC | null} */ this.mac = null;
		/** @type {WordArray | null} */ this.pass = null;
		/** @type {string | null} */ this.algName = null;
		/** @type {string | null} */ this.provName = null;
		/** @type {string | null} */ this.algProv = null;

		if (params !== undefined) {
			if (params['pass'] !== undefined) {
				this.setPassword(params['pass']);
			}
			if (params['alg'] !== undefined) {
				this.algName = params['alg'];
				if (params['prov'] === undefined)
					this.provName = DEFAULTPROVIDER[this.algName];
				this.setAlgAndProvider(this.algName, this.provName);
			}
		}
	}

	/**
	 * @param {string} alg 
	 * @param {string} prov 
	 */
	setAlgAndProvider(alg, prov) {
		alg = alg.toLowerCase();

		if (alg == null) alg = "hmacsha1";

		alg = alg.toLowerCase();
		if (alg.substr(0, 4) != "hmac") {
			throw "setAlgAndProvider unsupported HMAC alg: " + alg;
		}

		if (prov === undefined) prov = DEFAULTPROVIDER[alg];
		this.algProv = alg + "/" + prov;

		let hashAlg = alg.substr(4);

		// for cryptojs
		if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 && prov == 'cryptojs') {
			try {
				let mdObj = CRYPTOJSMESSAGEDIGESTNAME[hashAlg];
				this.mac = new HMAC(mdObj, this.pass);
			} catch (ex) {
				throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
			}
		}
	}

    /**
     * update digest by specified string
     * @param {string} str string to update
     * @description
     * @example
     * mac.updateString('New York');
     */
	updateString(str) {
		if (this.mac === null)
			throw "updateString(str) not supported for this alg/prov: " + this.algProv;
		this.mac.update(str);
	}

    /**
     * update digest by specified hexadecimal string
     * @param {string} hex hexadecimal string to update
     * @description
     * @example
     * mac.updateHex('0afe36');
     */
	updateHex(hex) {
		if (this.mac === null)
			throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
		let wHex = Hex.parse(hex);
		this.mac.update(wHex);
	}

    /**
     * completes hash calculation and returns hash result
     * @description
     * @example
     * mac.digest()
     */
	doFinal() {
		if (this.mac === null)
			throw "digest() not supported for this alg/prov: " + this.algProv;
		let hash = this.mac.finalize();
		return hash.toString(Hex);
	}

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @param {string} str string to final update
     * @description
     * @example
     * mac.digestString('aaa')
     */
	doFinalString(str) {
		if (this.mac === null)
			throw "digestString(str) not supported for this alg/prov: " + this.algProv;
		this.updateString(str);
		return this.doFinal();
	}

    /**
     * performs final update on the digest using hexadecimal string, 
     * then completes the digest computation
     * @param {string} hex hexadecimal string to final update
     * @description
     * @example
     * mac.digestHex('0f2abd')
     */
	doFinalHex(hex) {
		if (this.mac === null)
			throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
		this.updateHex(hex);
		return this.doFinal();
	}

    /**
     * set password for Mac
     * @param {Object<string,string> | string} pass password for Mac
     * @description
     * This method will set password for (H)Mac internally.
     * Argument 'pass' can be specified as following:
     * <ul>
     * <li>even length string of 0..9, a..f or A-F: implicitly specified as hexadecimal string</li>
     * <li>not above string: implicitly specified as raw string</li>
     * <li>{rstr: "\x65\x70"}: explicitly specified as raw string</li>
     * <li>{hex: "6570"}: explicitly specified as hexacedimal string</li>
     * <li>{utf8: "秘密"}: explicitly specified as UTF8 string</li>
     * <li>{b64: "Mi78..=="}: explicitly specified as Base64 string</li>
     * <li>{b64u: "Mi7-_"}: explicitly specified as Base64URL string</li>
     * </ul>
     * It is *STRONGLY RECOMMENDED* that explicit representation of password argument
     * to avoid ambiguity. For example string  "6161" can mean a string "6161" or 
     * a hexadecimal string of "aa" (i.e. \x61\x61).
     * @example
     * mac = KJUR.crypto.Mac({'alg': 'hmacsha256'});
     * // set password by implicit raw string
     * mac.setPassword("\x65\x70\xb9\x0b");
     * mac.setPassword("password");
     * // set password by implicit hexadecimal string
     * mac.setPassword("6570b90b");
     * mac.setPassword("6570B90B");
     * // set password by explicit raw string
     * mac.setPassword({"rstr": "\x65\x70\xb9\x0b"});
     * // set password by explicit hexadecimal string
     * mac.setPassword({"hex": "6570b90b"});
     * // set password by explicit utf8 string
     * mac.setPassword({"utf8": "passwordパスワード");
     * // set password by explicit Base64 string
     * mac.setPassword({"b64": "Mb+c3f/=="});
     * // set password by explicit Base64URL string
     * mac.setPassword({"b64u": "Mb-c3f_"});
     */
	setPassword(pass) {
		// internal this.pass shall be CryptoJS DWord Object for CryptoJS bug
		// work around. CrytoJS HMac password can be passed by
		// raw string as described in the manual however it doesn't
		// work properly in some case. If password was passed
		// by CryptoJS DWord which is not described in the manual
		// it seems to work. (fixed since crypto 1.1.7)

		if (typeof pass == 'string') {
			let hPass = pass;
			if (pass.length % 2 == 1 || !pass.match(/^[0-9A-Fa-f]+$/)) { // raw str
				hPass = rstrtohex(pass);
			}
			this.pass = Hex.parse(hPass);
			return;
		}

		if (pass != 'object')
			throw "KJUR.crypto.Mac unsupported password type: " + pass;

		/** @type {string | null} */ let hPass = null;
		if (pass['hex'] !== undefined) {
			if (pass['hex'].length % 2 != 0 || !pass['hex'].match(/^[0-9A-Fa-f]+$/))
				throw "Mac: wrong hex password: " + pass['hex'];
			hPass = pass['hex'];
		}
		if (pass['utf8'] !== undefined) hPass = utf8tohex(pass['utf8']);
		if (pass['rstr'] !== undefined) hPass = rstrtohex(pass['rstr']);
		if (pass['b64'] !== undefined) hPass = b64tohex(pass['b64']);
		if (pass['b64u'] !== undefined) hPass = b64utohex(pass['b64u']);

		if (hPass == null)
			throw "KJUR.crypto.Mac unsupported password type: " + pass;

		this.pass = Hex.parse(hPass);
	}
}

// ====== Signature class =========================================================
/**
 * Signature class which is very similar to java.security.Signature class
 * @property {string} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
 * @description
 * <br/>
 * As for params of constructor's argument, it can be specify following attributes:
 * <ul>
 * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}with{RSA,ECDSA,DSA})</li>
 * <li>provider - currently 'cryptojs/jsrsa' only</li>
 * </ul>
 * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
 * This Signature class supports following signature algorithm and provider names:
 * <ul>
 * <li>MD5withRSA - cryptojs/jsrsa</li>
 * <li>SHA1withRSA - cryptojs/jsrsa</li>
 * <li>SHA224withRSA - cryptojs/jsrsa</li>
 * <li>SHA256withRSA - cryptojs/jsrsa</li>
 * <li>SHA384withRSA - cryptojs/jsrsa</li>
 * <li>SHA512withRSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSA - cryptojs/jsrsa</li>
 * <li>MD5withECDSA - cryptojs/jsrsa</li>
 * <li>SHA1withECDSA - cryptojs/jsrsa</li>
 * <li>SHA224withECDSA - cryptojs/jsrsa</li>
 * <li>SHA256withECDSA - cryptojs/jsrsa</li>
 * <li>SHA384withECDSA - cryptojs/jsrsa</li>
 * <li>SHA512withECDSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withECDSA - cryptojs/jsrsa</li>
 * <li>MD5withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA224withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA256withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA384withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA512withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withDSA - cryptojs/jsrsa</li>
 * <li>SHA224withDSA - cryptojs/jsrsa</li>
 * <li>SHA256withDSA - cryptojs/jsrsa</li>
 * </ul>
 * Here are supported elliptic cryptographic curve names and their aliases for ECDSA:
 * <ul>
 * <li>secp256k1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1</li>
 * <li>secp384r1, NIST P-384, P-384</li>
 * </ul>
 * NOTE1: DSA signing algorithm is also supported since crypto 1.1.5.
 * <h4>EXAMPLES</h4>
 * @example
 * // RSA signature generation
 * let sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * let hSigVal = sig.sign();
 *
 * // DSA signature validation
 * let sig2 = new KJUR.crypto.Signature({"alg": "SHA1withDSA"});
 * sig2.init(certPEM);
 * sig.updateString('aaa');
 * let isValid = sig2.verify(hSigVal);
 * 
 * // ECDSA signing
 * let sig = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * let sigValueHex = sig.sign();
 *
 * // ECDSA verifying
 * let sig2 = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(certPEM);
 * sig.updateString('aaa');
 * let isValid = sig.verify(sigValueHex);
 */
export class Signature {
	/**
 	 * @param {Object<string, string>} params parameters for constructor
	 */
	constructor(params) {
		this.prvKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for signing
		this.pubKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for verifying

		/** @type {MessageDigest | null} */ this.md = null; // KJUR.crypto.MessageDigest object
		this.sig = null;
		/** @type {string | null} */ this.algName = null;
		/** @type {string | null} */ this.provName = null;
		/** @type {string | null} */ this.algProvName = null;
		/** @type {string | null} */ this.mdAlgName = null;
		/** @type {string | null} */ this.pubkeyAlgName = null;	// rsa,ecdsa,rsaandmgf1(=rsapss)
		this.state = null;
		this.pssSaltLen = -1;
		this.initParams = null;

		/** @type {string | null} */ this.sHashHex = null; // hex hash value for hex
		this.hDigestInfo = null;
		this.hPaddedDigestInfo = null;
		this.hSign = null;

		this.initParams = params;

		if (params !== undefined) {
			if (params['alg'] !== undefined) {
				this.algName = params['alg'];
				if (params['prov'] === undefined) {
					this.provName = DEFAULTPROVIDER[this.algName];
				} else {
					this.provName = params['prov'];
				}
				this.algProvName = this.algName + ":" + this.provName;
				this.setAlgAndProvider(this.algName, this.provName);
				this._setAlgNames();
			}
	
			if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'] | 0;
	
			if (params['prvkeypem'] !== undefined) {
				if (params['prvkeypas'] !== undefined) {
					throw "both prvkeypem and prvkeypas parameters not supported";
				} else {
					try {
						let prvKey = KEYUTIL.getKey(params['prvkeypem']);
						this.init(prvKey);
					} catch (ex) {
						throw "fatal error to load pem private key: " + ex;
					}
				}
			}
		}
	}

	/** @private */
	_setAlgNames() {
		let matchResult = this.algName.match(/^(.+)with(.+)$/);
		if (matchResult) {
			this.mdAlgName = matchResult[1].toLowerCase();
			this.pubkeyAlgName = matchResult[2].toLowerCase();
		}
	}

	/**
	 * @private
	 * @param {string} hex
	 * @param {number} bitLength
	 */
	_zeroPaddingOfSignature(hex, bitLength) {
		let s = "";
		let nZero = bitLength / 4 - hex.length;
		for (let i = 0; i < nZero; i++) {
			s = s + "0";
		}
		return s + hex;
	}

    /**
     * set signature algorithm and provider
     * @param {string} alg signature algorithm name
     * @param {string} prov provider name
     * @description
     * @example
     * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
     */
	setAlgAndProvider(alg, prov) {
		this._setAlgNames();
		if (prov != 'cryptojs/jsrsa')
			throw "provider not supported: " + prov;

		if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
			try {
				this.md = new MessageDigest({ 'alg': this.mdAlgName });
			} catch (ex) {
				throw "setAlgAndProvider hash alg set fail alg=" +
				this.mdAlgName + "/" + ex;
			}
		}
	}

    /**
     * Initialize this object for signing or verifying depends on key
     * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
     * @param {string} pass (OPTION) passcode for encrypted private key
     * @description
     * This method is very useful initialize method for Signature class since
     * you just specify key then this method will automatically initialize it
     * using {@link KEYUTIL.getKey} method.
     * As for 'key',  following argument type are supported:
     * <h5>signing</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
     * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
     * <li>RSAKey object of private key</li>
     * <li>KJUR.crypto.ECDSA object of private key</li>
     * <li>KJUR.crypto.DSA object of private key</li>
     * </ul>
     * <h5>verification</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
     * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
     *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
     * <li>RSAKey object of public key</li>
     * <li>KJUR.crypto.ECDSA object of public key</li>
     * <li>KJUR.crypto.DSA object of public key</li>
     * </ul>
     * @example
     * sig.init(sCertPEM)
     */
	init(key, pass) {
		if (this.md === null)
			throw "init(key, pass) not supported for this alg:prov=" + this.algProvName;

		let keyObj = null;
		try {
			if (pass === undefined) {
				keyObj = KEYUTIL.getKey(key);
			} else {
				keyObj = KEYUTIL.getKey(key, pass);
			}
		} catch (ex) {
			throw "init failed:" + ex;
		}

		if (keyObj.isPrivate === true) {
			this.prvKey = keyObj;
			this.state = "SIGN";
		} else if (keyObj.isPublic === true) {
			this.pubKey = keyObj;
			this.state = "VERIFY";
		} else {
			throw "init failed.:" + keyObj;
		}
	}

    /**
     * Updates the data to be signed or verified by a string
     * @param {string} str string to use for the update
     * @description
     * @example
     * sig.updateString('aaa')
     */
	updateString(str) {
		if (this.md === null)
			throw "updateString(str) not supported for this alg:prov=" + this.algProvName;

		this.md.updateString(str);
	}

    /**
     * Updates the data to be signed or verified by a hexadecimal string
     * @param {string} hex hexadecimal string to use for the update
     * @description
     * @example
     * sig.updateHex('1f2f3f')
     */
	updateHex(hex) {
		if (this.md === null)
			throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;

		this.md.updateHex(hex);
	}

    /**
     * Returns the signature bytes of all data updates as a hexadecimal string
     * @return the signature bytes as a hexadecimal string
     * @description
     * @example
     * let hSigValue = sig.sign()
     */
	sign() {
		if (this.md === null)
			throw "sign() not supported for this alg:prov=" + this.algProvName;

		this.sHashHex = this.md.digest();
		if (typeof this.ecprvhex != "undefined" &&
			typeof this.eccurvename != "undefined") {
			let ec = new KJUR.crypto.ECDSA({ 'curve': this.eccurvename });
			this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
		} else if (this.prvKey instanceof RSAKey &&
			this.pubkeyAlgName === "rsaandmgf1") {
			this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
				this.mdAlgName,
				this.pssSaltLen);
		} else if (this.prvKey instanceof RSAKey &&
			this.pubkeyAlgName === "rsa") {
			this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
				this.mdAlgName);
		} else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
			this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else if (this.prvKey instanceof KJUR.crypto.DSA) {
			this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else {
			throw "Signature: unsupported private key alg: " + this.pubkeyAlgName;
		}
		return this.hSign;
	}

    /**
     * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
     * @param {string} str string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * let hSigValue = sig.signString('aaa')
     */
	signString(str) {
		if (this.md === null)
			throw "digestString(str) not supported for this alg:prov=" + this.algProvName;

		this.updateString(str);
		return this.sign();
	}

    /**
     * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
     * @param {string} hex hexadecimal string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * let hSigValue = sig.signHex('1fdc33')
     */
	signHex(hex) {
		if (this.md === null)
			throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;

		this.updateHex(hex);
		return this.sign();
	}

    /**
     * verifies the passed-in signature.
     * @param {string} str string to final update
     * @return {boolean} true if the signature was verified, otherwise false
     * @description
     * @example
     * let isValid = sig.verify('1fbcefdca4823a7(snip)')
     */
	verify(hSigVal) {
		if (this.md === null)
			throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;

		this.sHashHex = this.md.digest();
		if (typeof this.ecpubhex != "undefined" &&
			typeof this.eccurvename != "undefined") {
			let ec = new KJUR.crypto.ECDSA({ curve: this.eccurvename });
			return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
		} else if (this.pubKey instanceof RSAKey &&
			this.pubkeyAlgName === "rsaandmgf1") {
			return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal,
				this.mdAlgName,
				this.pssSaltLen);
		} else if (this.pubKey instanceof RSAKey &&
			this.pubkeyAlgName === "rsa") {
			return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (KJUR.crypto.ECDSA !== undefined &&
			this.pubKey instanceof KJUR.crypto.ECDSA) {
			return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (KJUR.crypto.DSA !== undefined &&
			this.pubKey instanceof KJUR.crypto.DSA) {
			return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else {
			throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
	}
}

// ====== Cipher class ============================================================
/**
 * Cipher class to encrypt and decrypt data<br/> * @param {Array} params parameters for constructor
 * @description
 * Here is supported canonicalized cipher algorithm names and its standard names:
 * <ul>
 * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKey)</li>
 * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
 * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
 * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
 * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
 * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
 * </ul>
 * NOTE: (*) is not supported in Java JCE.<br/>
 * Currently this class supports only RSA encryption and decryption. 
 * However it is planning to implement also symmetric ciphers near in the future.
 * @example
 */
KJUR.crypto.export function Cipher(params) {
};

/**
 * encrypt raw string by specified key and algorithm<br/>
 * @param {string} s input string to encrypt
 * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption 
 * @return {string} hexadecimal encrypted string
 * @description
 * This static method encrypts raw string with specified key and algorithm.
 * @example 
 * KJUR.crypto.Cipher.encrypt("aaa", pubRSAKeyObj) &rarr; "1abc2d..."
 * KJUR.crypto.Cipher.encrypt("aaa", pubRSAKeyObj, "RSAOAEP") &rarr; "23ab02..."
 */
KJUR.crypto.Cipher.export function encrypt(s, keyObj, algName) {
	if (keyObj instanceof RSAKey && keyObj.isPublic) {
		let algName2 = KJUR.crypto.Cipher.getAlgByKeyAndName(keyObj, algName);
		if (algName2 === "RSA") return keyObj.encrypt(s);
		if (algName2 === "RSAOAEP") return keyObj.encryptOAEP(s, "sha1");

		let a = algName2.match(/^RSAOAEP(\d+)$/);
		if (a !== null) return keyObj.encryptOAEP(s, "sha" + a[1]);

		throw "Cipher.encrypt: unsupported algorithm for RSAKey: " + algName;
	} else {
		throw "Cipher.encrypt: unsupported key or algorithm";
	}
};

/**
 * decrypt encrypted hexadecimal string with specified key and algorithm<br/>
 * @param {string} hex hexadecial string of encrypted message
 * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption
 * @return {string} hexadecimal encrypted string
 * @description
 * This static method decrypts encrypted hexadecimal string with specified key and algorithm.
 * @example 
 * KJUR.crypto.Cipher.decrypt("aaa", prvRSAKeyObj) &rarr; "1abc2d..."
 * KJUR.crypto.Cipher.decrypt("aaa", prvRSAKeyObj, "RSAOAEP) &rarr; "23ab02..."
 */
KJUR.crypto.Cipher.export function decrypt(hex, keyObj, algName) {
	if (keyObj instanceof RSAKey && keyObj.isPrivate) {
		let algName2 = KJUR.crypto.Cipher.getAlgByKeyAndName(keyObj, algName);
		if (algName2 === "RSA") return keyObj.decrypt(hex);
		if (algName2 === "RSAOAEP") return keyObj.decryptOAEP(hex, "sha1");

		let a = algName2.match(/^RSAOAEP(\d+)$/);
		if (a !== null) return keyObj.decryptOAEP(hex, "sha" + a[1]);

		throw "Cipher.decrypt: unsupported algorithm for RSAKey: " + algName;
	} else {
		throw "Cipher.decrypt: unsupported key or algorithm";
	}
};

/**
 * get canonicalized encrypt/decrypt algorithm name by key and short/long algorithm name<br/>
 * @param {Object} keyObj RSAKey object or hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption
 * @return {string} canonicalized algorithm name for encryption/decryption
 * @description
 * Here is supported canonicalized cipher algorithm names and its standard names:
 * <ul>
 * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKey)</li>
 * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
 * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
 * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
 * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
 * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
 * </ul>
 * NOTE: (*) is not supported in Java JCE.
 * @example 
 * KJUR.crypto.Cipher.getAlgByKeyAndName(objRSAKey) &rarr; "RSA"
 * KJUR.crypto.Cipher.getAlgByKeyAndName(objRSAKey, "RSAOAEP") &rarr; "RSAOAEP"
 */
KJUR.crypto.Cipher.export function getAlgByKeyAndName(keyObj, algName) {
	if (keyObj instanceof RSAKey) {
		if (":RSA:RSAOAEP:RSAOAEP224:RSAOAEP256:RSAOAEP384:RSAOAEP512:".indexOf(algName) != -1)
			return algName;
		if (algName === null || algName === undefined) return "RSA";
		throw "getAlgByKeyAndName: not supported algorithm name for RSAKey: " + algName;
	}
	throw "getAlgByKeyAndName: not supported algorithm name: " + algName;
}

// ====== Other Utility class =====================================================

/**
 * static object for cryptographic function utilities
 * @property {Array} oidhex2name key value of hexadecimal OID and its name
 *           (ex. '2a8648ce3d030107' and 'secp256r1')
 * @description
 */
KJUR.crypto.OID = new function () {
	this.oidhex2name = {
		'2a864886f70d010101': 'rsaEncryption',
		'2a8648ce3d0201': 'ecPublicKey',
		'2a8648ce380401': 'dsa',
		'2a8648ce3d030107': 'secp256r1',
		'2b8104001f': 'secp192k1',
		'2b81040021': 'secp224r1',
		'2b8104000a': 'secp256k1',
		'2b81040023': 'secp521r1',
		'2b81040022': 'secp384r1',
		'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
		'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
		'608648016503040302': 'SHA256withDSA', // 2.16.840.1.101.3.4.3.2
	};
};
