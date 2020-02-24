/*
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

import { RSAKeyEx } from "./rsaex.js"

/**
 * Cipher module to encrypt and decrypt data<br/>
 * @description
 * Here is supported canonicalized cipher algorithm names and its standard names:
 * <ul>
 * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKeyEx)</li>
 * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
 * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
 * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
 * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
 * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
 * </ul>
 * NOTE: (*) is not supported in Java JCE.<br/>
 * Currently this module supports only RSA encryption and decryption. 
 * However it is planning to implement also symmetric ciphers near in the future.
 * @example
 */

 /**
 * encrypt raw string by specified key and algorithm<br/>
 * @param {string} s input string to encrypt
 * @param {Object} keyObj RSAKeyEx object or hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption 
 * @return {string} hexadecimal encrypted string
 * @description
 * This static method encrypts raw string with specified key and algorithm.
 * @example 
 * encrypt("aaa", pubRSAKeyExObj) &rarr; "1abc2d..."
 * encrypt("aaa", pubRSAKeyExObj, "RSAOAEP") &rarr; "23ab02..."
 */
export function encrypt(s, keyObj, algName) {
	if (keyObj instanceof RSAKeyEx && keyObj.isPublic) {
		let algName2 = getAlgByKeyAndName(keyObj, algName);
		if (algName2 === "RSA") return keyObj.encrypt(s);
		if (algName2 === "RSAOAEP") return keyObj.encryptOAEP(s, "sha1");

		let a = algName2.match(/^RSAOAEP(\d+)$/);
		if (a !== null) return keyObj.encryptOAEP(s, "sha" + a[1]);

		throw "Cipher.encrypt: unsupported algorithm for RSAKeyEx: " + algName;
	} else {
		throw "Cipher.encrypt: unsupported key or algorithm";
	}
}

/**
 * decrypt encrypted hexadecimal string with specified key and algorithm<br/>
 * @param {string} hex hexadecial string of encrypted message
 * @param {Object} keyObj RSAKeyEx object or hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption
 * @return {string} hexadecimal encrypted string
 * @description
 * This static method decrypts encrypted hexadecimal string with specified key and algorithm.
 * @example 
 * decrypt("aaa", prvRSAKeyExObj) &rarr; "1abc2d..."
 * decrypt("aaa", prvRSAKeyExObj, "RSAOAEP) &rarr; "23ab02..."
 */
export function decrypt(hex, keyObj, algName) {
	if (keyObj instanceof RSAKeyEx && keyObj.isPrivate) {
		let algName2 = getAlgByKeyAndName(keyObj, algName);
		if (algName2 === "RSA") return keyObj.decrypt(hex);
		if (algName2 === "RSAOAEP") return keyObj.decryptOAEP(hex, "sha1");

		let a = algName2.match(/^RSAOAEP(\d+)$/);
		if (a !== null) return keyObj.decryptOAEP(hex, "sha" + a[1]);

		throw "Cipher.decrypt: unsupported algorithm for RSAKeyEx: " + algName;
	} else {
		throw "Cipher.decrypt: unsupported key or algorithm";
	}
}

/**
 * get canonicalized encrypt/decrypt algorithm name by key and short/long algorithm name<br/>
 * @param {Object} keyObj RSAKeyEx object or hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption
 * @return {string} canonicalized algorithm name for encryption/decryption
 * @description
 * Here is supported canonicalized cipher algorithm names and its standard names:
 * <ul>
 * <li>RSA - RSA/ECB/PKCS1Padding (default for RSAKeyEx)</li>
 * <li>RSAOAEP - RSA/ECB/OAEPWithSHA-1AndMGF1Padding</li>
 * <li>RSAOAEP224 - RSA/ECB/OAEPWithSHA-224AndMGF1Padding(*)</li>
 * <li>RSAOAEP256 - RSA/ECB/OAEPWithSHA-256AndMGF1Padding</li>
 * <li>RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding(*)</li>
 * <li>RSAOAEP512 - RSA/ECB/OAEPWithSHA-512AndMGF1Padding(*)</li>
 * </ul>
 * NOTE: (*) is not supported in Java JCE.
 * @example 
 * getAlgByKeyAndName(objRSAKeyEx) &rarr; "RSA"
 * getAlgByKeyAndName(objRSAKeyEx, "RSAOAEP") &rarr; "RSAOAEP"
 */
export function getAlgByKeyAndName(keyObj, algName) {
	if (keyObj instanceof RSAKeyEx) {
		if (":RSA:RSAOAEP:RSAOAEP224:RSAOAEP256:RSAOAEP384:RSAOAEP512:".indexOf(algName) != -1)
			return algName;
		if (algName === null || algName === undefined) return "RSA";
		throw "getAlgByKeyAndName: not supported algorithm name for RSAKeyEx: " + algName;
	}
	throw "getAlgByKeyAndName: not supported algorithm name: " + algName;
}
