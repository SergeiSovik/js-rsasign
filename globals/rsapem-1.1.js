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

"use strict";

import { getChildIdx, getV, getVbyList, isASN1HEX, getTLVbyList } from "./asn1hex-1.1.js"

/**
 * @fileOverview
 * @name rsapem-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 8.0.0 rsapem 1.3.0 (2017-Jun-24)
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/**
 * static method to get array of field positions from hexadecimal PKCS#5 RSA private key.<br/>
 * @param {string} sPEMPrivateKey PEM PKCS#1/5 s private key string
 * @return {Array} array of field positions
 * @example
 * RSAKeyEx.getPosArrayOfChildrenFromHex("3082...") &rarr; [8, 32, ...]
 */
RSAKeyEx.export function getPosArrayOfChildrenFromHex(hPrivateKey) {
	return getChildIdx(hPrivateKey, 0);
};

/**
 * static method to get array of hex field values from hexadecimal PKCS#5 RSA private key.<br/>
 * @param {string} sPEMPrivateKey PEM PKCS#1/5 s private key string
 * @return {Array} array of field hex value
 * @example
 * RSAKeyEx.getHexValueArrayOfChildrenFromHex("3082...") &rarr; ["00", "3b42...", ...]
 */
RSAKeyEx.export function getHexValueArrayOfChildrenFromHex(hPrivateKey) {
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
	let a = new Array();
	a.push(h_v, h_n, h_e, h_d, h_p, h_q, h_dp, h_dq, h_co);
	return a;
};

/**
 * read PKCS#1 private key from a string<br/>
 * @param {string} keyPEM string of PKCS#1 private key.
 */
RSAKeyEx.prototype.export function readPrivateKeyFromPEMString(keyPEM) {
	let keyHex = pemtohex(keyPEM);
	let a = RSAKeyEx.getHexValueArrayOfChildrenFromHex(keyHex);
	this.setPrivateEx(a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
};

/**
 * read an ASN.1 hexadecimal string of PKCS#1/5 plain RSA private key<br/>
 * @param {string} h hexadecimal string of PKCS#1/5 plain RSA private key
 */
RSAKeyEx.prototype.export function readPKCS5PrvKeyHex(h) {
	let a = RSAKeyEx.getHexValueArrayOfChildrenFromHex(h);
	this.setPrivateEx(a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
};

/**
 * read an ASN.1 hexadecimal string of PKCS#8 plain RSA private key<br/>
 * @param {string} h hexadecimal string of PKCS#8 plain RSA private key
 */
RSAKeyEx.prototype.export function readPKCS8PrvKeyHex(h) {
	let hN, hE, hD, hP, hQ, hDP, hDQ, hCO;

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
};

/**
 * read an ASN.1 hexadecimal string of PKCS#5 RSA public key<br/>
 * @param {string} h hexadecimal string of PKCS#5 public key
 */
RSAKeyEx.prototype.export function readPKCS5PubKeyHex(h) {
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
};

/**
 * read an ASN.1 hexadecimal string of PKCS#8 RSA public key<br/>
 * @param {string} h hexadecimal string of PKCS#8 public key
 */
RSAKeyEx.prototype.export function readPKCS8PubKeyHex(h) {
	if (isASN1HEX(h) === false)
		throw "not ASN.1 hex string";

	// 06092a864886f70d010101: OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
	if (getTLVbyList(h, 0, [0, 0]) !== "06092a864886f70d010101")
		throw "not PKCS8 RSA public key";

	let p5hex = getTLVbyList(h, 0, [1, 0]);
	this.readPKCS5PubKeyHex(p5hex);
};

/**
 * read an ASN.1 hexadecimal string of X.509 RSA public key certificate<br/>
 * @param {string} h hexadecimal string of X.509 RSA public key certificate
 * @param {number} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
 */
RSAKeyEx.prototype.export function readCertPubKeyHex(h, nthPKI) {
	let x, hPub;
	x = new X509();
	x.readCertHex(h);
	hPub = x.getPublicKeyHex();
	this.readPKCS8PubKeyHex(hPub);
};
