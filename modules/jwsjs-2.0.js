/*
 * jwsjs.js - JSON Web Signature JSON Serialization (JWSJS) Class
 *
 * Original work Copyright (c) 2010-2018 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { Dictionary } from "./../../../include/type.js"
import { readSafeJSONString, sign, verify } from "./jws-3.3.js"
import { KeyObject } from "./keyutil-1.0.js"

/**
 * JSON Web Signature JSON Serialization (JWSJS) class.<br/>
 * @description
 * This class generates and verfies "JSON Web Signature JSON Serialization (JWSJS)" of
 * <a href="http://tools.ietf.org/html/draft-jones-json-web-signature-json-serialization-01">
 * IETF Internet Draft</a>. Here is major methods of this class:
 * <ul>
 * <li>{@link JWSJS#readJWSJS} - initialize with string or JSON object of JWSJS.</li>
 * <li>{@link JWSJS#initWithJWS} - initialize with JWS as first signature.</li>
 * <li>{@link JWSJS#addSignature} - append signature to JWSJS object.</li>
 * <li>{@link JWSJS#verifyAll} - verify all signatures in JWSJS object.</li>
 * <li>{@link JWSJS#getJSON} - get result of JWSJS object as JSON object.</li>
 * </ul>
 *
 * @example
 * // initialize
 * jwsjs1 = new JWSJS();
 * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
 * 
 * // add PS256 signature with RSA private key object
 * prvKeyObj = getKey("-----BEGIN PRIVATE KEY...");
 * jwsjs1.addSignature("PS256", {alg: "PS256"}, prvKeyObj);
 * // add HS256 signature with HMAC password "secret"
 * jwsjs1.addSignature(null, {alg: "HS256"}, {utf8: "secret"});
 * 
 * // get result finally
 * jwsjsObj1 = jwsjs1.getJSON();
 *
 * // verify all signatures
 * isValid = jwsjs1.verifyAll([["-----BEGIN CERT...", ["RS256"]],
 *                             [{utf8: "secret"}, ["HS256"]]]); 
 * 
 */
export class JWSJS {
	constructor() {
		/** @type {Array<string>} */ this.aHeader = [];
		/** @type {string | null} */ this.sPayload = null;
		/** @type {Array<string>} */ this.aSignature = [];
		/** @type {Dictionary | null} */ this.aSignatures = null;
	}

    /**
     * (re-)initialize this object.<br/>
     */
	init() {
		this.aHeader = [];
		this.sPayload = null;
		this.aSignature = [];
	}

    /**
     * (re-)initialize and set first signature with JWS.<br/>
     * @param {string} sJWS JWS signature to set
         * @example
     * jwsjs1 = new JWSJWS();
     * jwsjs1.initWithJWS("eyJ...");
     */
	initWithJWS(sJWS) {
		this.init();

		let a = sJWS.split(".");
		if (a.length != 3)
			throw "malformed input JWS";

		this.aHeader.push(a[0]);
		this.sPayload = a[1];
		this.aSignature.push(a[2]);
	}

	// == add signature =======================================================
	/**
	 * add a signature to existing JWS-JS by algorithm, header and key.<br/>
	 * @param {string} alg JWS algorithm. If null, alg in header will be used.
	 * @param {string | Dictionary} spHead string or object of JWS Header to add.
	 * @param {KeyObject | string} key JWS key to sign. key object, PEM private key or HMAC key
	 * @param {string} pass optional password for encrypted PEM private key
	 * @throws {string} if signature append failed.
	 * @example
	 * // initialize
	 * jwsjs1 = new JWSJS();
	 * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
	 *
	 * // add PS256 signature with RSA private key object
	 * prvKeyObj = getKey("-----BEGIN PRIVATE KEY...");
	 * jwsjs1.addSignature("PS256", {alg: "PS256"}, prvKeyObj);
	 *
	 * // add HS256 signature with HMAC password "secret"
	 * jwsjs1.addSignature(null, {alg: "HS256"}, {utf8: "secret"});
	 *
	 * // get result finally
	 * jwsjsObj1 = jwsjs1.getJSON();
	 */
	addSignature(alg, spHead, key, pass) {
		if (this.sPayload === undefined || this.sPayload === null)
			throw "there's no JSON-JS signature to add.";

		let sigLen = this.aHeader.length;
		if (this.aHeader.length != this.aSignature.length)
			throw "aHeader.length != aSignature.length";

		try {
			let sJWS = sign(alg, spHead, this.sPayload, key, pass);
			let a = sJWS.split(".");
			let sHeader2 = a[0];
			let sSignature2 = a[2];
			this.aHeader.push(a[0]);
			this.aSignature.push(a[2]);
		} catch (ex) {
			if (this.aHeader.length > sigLen) this.aHeader.pop();
			if (this.aSignature.length > sigLen) this.aSignature.pop();
			throw "addSignature failed: " + ex;
		}
	}

	// == verify signature ====================================================
	/**
	 * verify all signature of JWS-JS object by array of key and acceptAlgs.<br/>
	 * @param {Array<Array>} aKeyAlg a array of key and acceptAlgs
	 * @return true if all signatures are valid otherwise false
	 * @example
	 * jwsjs1 = new JWSJS();
	 * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
	 * isValid = jwsjs1.verifyAll([["-----BEGIN CERT...", ["RS256"]],
	 *                             [{utf8: "secret"}, ["HS256"]]]); 
	 */
	verifyAll(aKeyAlg) {
		if (this.aHeader.length !== aKeyAlg.length ||
			this.aSignature.length !== aKeyAlg.length)
			return false;

		for (let i = 0; i < aKeyAlg.length; i++) {
			let keyAlg = aKeyAlg[i];
			if (keyAlg.length !== 2) return false;
			let result = this.verifyNth(i, keyAlg[0], keyAlg[1]);
			if (result === false) return false;
		}
		return true;
	}

	/**
	 * verify Nth signature of JWS-JS object by key and acceptAlgs.<br/>
	 * @param {number} idx nth index of JWS-JS signature to verify
	 * @param {string | KeyObject | Dictionary} key key to verify
	 * @param {Array<string>} acceptAlgs array of acceptable signature algorithms
	 * @return true if signature is valid otherwise false
	 * @example
	 * jwsjs1 = new JWSJS();
	 * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
	 * isValid1 = jwsjs1.verifyNth(0, "-----BEGIN CERT...", ["RS256"]);
	 * isValid2 = jwsjs1.verifyNth(1, {utf8: "secret"}, ["HS256"]);
	 */
	verifyNth(idx, key, acceptAlgs) {
		if (this.aHeader.length <= idx || this.aSignature.length <= idx)
			return false;
		let sHeader = this.aHeader[idx];
		let sSignature = this.aSignature[idx];
		let sJWS = sHeader + "." + this.sPayload + "." + sSignature;
		let result = false;
		try {
			result = verify(sJWS, key, acceptAlgs);
		} catch (ex) {
			return false;
		}
		return result;
	}

	/**
	 * read JWS-JS string or object<br/>
	 * @param {string | Dictionary} spJWSJS string or JSON object of JWS-JS to load.
	 * @throws {string} if sJWSJS is malformed or not JSON string.
	 * @description
	 * NOTE: Loading from JSON object is suppored from 
	 * jsjws 2.1.0 jsrsasign 5.1.0 (2016-Sep-06).
	 * @example
	 * // load JWSJS from string
	 * jwsjs1 = new JWSJS();
	 * jwsjs1.readJWSJS("{headers: [...], payload: "eyJ...", signatures: [...]}");
	 *
	 * // load JWSJS from JSON object
	 * jwsjs1 = new JWSJS();
	 * jwsjs1.readJWSJS({headers: [...], payload: "eyJ...", signatures: [...]});
	 */
	readJWSJS(spJWSJS) {
		if (typeof spJWSJS === "string") {
			let oJWSJS = readSafeJSONString(spJWSJS);
			if (oJWSJS == null) throw "argument is not safe JSON object string";

			this.aHeader = oJWSJS['headers'];
			this.sPayload = oJWSJS['payload'];
			this.aSignature = oJWSJS['signatures'];
		} else {
			try {
				if (spJWSJS['headers'].length > 0) {
					this.aHeader = spJWSJS['headers'];
				} else {
					throw "malformed header";
				}
				if (typeof spJWSJS['payload'] === "string") {
					this.sPayload = spJWSJS['payload'];
				} else {
					throw "malformed signatures";
				}
				if (spJWSJS['signatures'].length > 0) {
					this.aSignatures = spJWSJS['signatures'];
				} else {
					throw "malformed signatures";
				}
			} catch (ex) {
				throw "malformed JWS-JS JSON object: " + ex;
			}
		}
	}

	// == utility =============================================================
	/**
	 * get JSON object for this JWS-JS object.<br/>
	 * @example
	 * jwsj1 = new JWSJS();
	 * // do some jwsj1 operation then get result by getJSON()
	 * jwsjsObj1 = jwsjs1.getJSON();
	 * // jwsjsObj1 &rarr; { headers: [...], payload: "ey...", signatures: [...] }
	 */
	getJSON() {
		return {
			"headers": this.aHeader,
			"payload": this.sPayload,
			"signatures": this.aSignature
		};
	}

	/**
	 * check if this JWS-JS object is empty.<br/>
	 * @return 1 if there is no signatures in this object, otherwise 0.
	 */
	isEmpty() {
		if (this.aHeader.length == 0) return 1;
		return 0;
	}
}
