/*
 * asn1ocsp.js - ASN.1 DER encoder classes for OCSP protocol
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

import { ASN1Object, DERInteger, DEROctetString, DERSequence } from "./asn1-1.0.js"
import { AlgorithmIdentifier } from "./asn1x509-1.0.js"
import { hashHex } from "./crypto-1.1.js"
import { getTLVbyList, getIdxbyList, getVbyList, getV } from "./asn1hex-1.1.js"
import { Dictionary } from "./../../../include/type.js"
import { X509 } from "./x509-1.1.js"
import { hextoutf8 } from "./base64x-1.1.js"

/**
 * ASN.1 module for OCSP protocol<br/>
 * <p>
 * This module provides 
 * <a href="https://tools.ietf.org/html/rfc6960">RFC 6960
 * Online Certificate Status Protocol (OCSP)</a> ASN.1 request and response generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate OCSP data</li>
 * </ul>
 * 
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * <li>{@link CertID} for ASN.1 class as defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link Request} for ASN.1 class as defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link TBSRequest} for ASN.1 class as defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link OCSPRequest} for ASN.1 class as defined in
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. </li>
 * <li>{@link OCSPUtil} for static utility methods.</li>
 * </ul>
 * </p>
 */

const DEFAULT_HASH = "sha1";

/**
 * ASN.1 CertID class for OCSP<br/>
 * @description
 * CertID ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * <pre>
 * CertID ::= SEQUENCE {
 *   hashAlgorithm   AlgorithmIdentifier,
 *   issuerNameHash  OCTET STRING, -- Hash of issuer's DN
 *   issuerKeyHash   OCTET STRING, -- Hash of issuer's public key
 *   serialNumber    CertificateSerialNumber }
 * </pre>
 * @example
 * // default constructor
 * o = new CertID();
 * // constructor with certs (sha1 is used by default)
 * o = new CertID({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN..."});
 * // constructor with certs and sha256
 * o = new CertID({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"});
 * // constructor with values
 * o = new CertID({namehash: "1a...", keyhash: "ad...", serial: "1234", alg: "sha256"});
 */
export class CertID extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		/** @type {AlgorithmIdentifier | null} */ this.dHashAlg = null;
		/** @type {DEROctetString | null} */ this.dIssuerNameHash = null;
		/** @type {DEROctetString | null} */ this.dIssuerKeyHash = null;
		/** @type {DERInteger | null} */ this.dSerialNumber = null;

		if (params !== undefined) {
			let p = params;
			if (p.issuerCert !== undefined &&
				p.subjectCert !== undefined) {
				let alg = DEFAULT_HASH;
				if (p.alg === undefined) alg = undefined;
				this.setByCert(p.issuerCert, p.subjectCert, alg);
			} else if (p.namehash !== undefined &&
				p.keyhash !== undefined &&
				p.serial !== undefined) {
				let alg = DEFAULT_HASH;
				if (p.alg === undefined) alg = undefined;
				this.setByValue(p.namehash, p.keyhash, p.serial, alg);
			} else {
				throw "invalid constructor arguments";
			}
		}
	}

    /**
     * set CertID ASN.1 object by values.<br/>
     * @param {string} issuerNameHashHex hexadecimal string of hash value of issuer name
     * @param {string} issuerKeyHashHex hexadecimal string of hash value of issuer public key
     * @param {string} serialNumberHex hexadecimal string of certificate serial number to be verified
     * @param {string} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
     * @example
     * o = new CertID();
     * o.setByValue("1fac...", "fd3a...", "1234"); // sha1 is used by default
     * o.setByValue("1fac...", "fd3a...", "1234", "sha256");
     */
	setByValue(issuerNameHashHex, issuerKeyHashHex,
		serialNumberHex, algName) {
		if (algName === undefined) algName = DEFAULT_HASH;
		this.dHashAlg = new AlgorithmIdentifier({ name: algName });
		this.dIssuerNameHash = new DEROctetString({ hex: issuerNameHashHex });
		this.dIssuerKeyHash = new DEROctetString({ hex: issuerKeyHashHex });
		this.dSerialNumber = new DERInteger({ hex: serialNumberHex });
	}

    /**
     * set CertID ASN.1 object by PEM certificates.<br/>
     * @param {string} issuerCert string of PEM issuer certificate
     * @param {string} subjectCert string of PEM subject certificate to be verified by OCSP
     * @param {string} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
     * @example
     * o = new CertID();
     * o.setByCert("-----BEGIN...", "-----BEGIN..."); // sha1 is used by default
     * o.setByCert("-----BEGIN...", "-----BEGIN...", "sha256");
     */
	setByCert(issuerCert, subjectCert, algName) {
		if (algName === undefined) algName = DEFAULT_HASH;

		let xSbj = new X509();
		xSbj.readCertPEM(subjectCert);
		let xIss = new X509();
		xIss.readCertPEM(issuerCert);

		let hISS_SPKI = xIss.getPublicKeyHex();
		let issuerKeyHex = getTLVbyList(hISS_SPKI, 0, [1, 0], "30");

		let serialNumberHex = xSbj.getSerialNumberHex();
		let issuerNameHashHex = hashHex(xIss.getSubjectHex(), algName);
		let issuerKeyHashHex = hashHex(issuerKeyHex, algName);
		this.setByValue(issuerNameHashHex, issuerKeyHashHex,
			serialNumberHex, algName);
		this.hoge = xSbj.getSerialNumberHex();
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.dHashAlg === null &&
			this.dIssuerNameHash === null &&
			this.dIssuerKeyHash === null &&
			this.dSerialNumber === null)
			throw "not yet set values";

		let a = [this.dHashAlg, this.dIssuerNameHash,
		this.dIssuerKeyHash, this.dSerialNumber];
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * ASN.1 Request class for OCSP<br/>
 * @description
 * Request ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * singleRequestExtensions is not supported yet in this version such as nonce.
 * <pre>
 * Request ::= SEQUENCE {
 *   reqCert                  CertID,
 *   singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL }
 * </pre>
 * @example
 * // default constructor
 * o = new Request();
 * // constructor with certs (sha1 is used by default)
 * o = new Request({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN..."});
 * // constructor with certs and sha256
 * o = new Request({issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"});
 * // constructor with values
 * o = new Request({namehash: "1a...", keyhash: "ad...", serial: "1234", alg: "sha256"});
 */
export class Request extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {CertID | null} */ this.dReqCert = null;
		this.dExt = null;

		if (typeof params !== "undefined") {
			let o = new CertID(params);
			this.dReqCert = o;
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let a = [];

		// 1. reqCert
		if (this.dReqCert === null)
			throw "reqCert not set";
		a.push(this.dReqCert);

		// 2. singleRequestExtensions (not supported yet)

		// 3. construct SEQUENCE
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * ASN.1 TBSRequest class for OCSP<br/>
 * @description
 * TBSRequest ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * <pre>
 * TBSRequest ::= SEQUENCE {
 *   version            [0] EXPLICIT Version DEFAULT v1,
 *   requestorName      [1] EXPLICIT GeneralName OPTIONAL,
 *   requestList            SEQUENCE OF Request,
 *   requestExtensions  [2] EXPLICIT Extensions OPTIONAL }
 * </pre>
 * @example
 * // default constructor
 * o = new TBSRequest();
 * // constructor with requestList parameter
 * o = new TBSRequest({reqList:[
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg:},
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"}
 * ]});
 */
export class TBSRequest extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		/** @type {number} */ this.version = 0;
		/** @type {string | null} */ this.dRequestorName = null;
		/** @type {Array<Request> | null} */ this.dRequestList = [];
		this.dRequestExt = null;

		if (params !== undefined) {
			if (params['reqList'] !== undefined)
				this.setRequestListByParam(params['reqList']);
		}
	}

    /**
     * set TBSRequest ASN.1 object by array of parameters.<br/>
     * @param {Array<Dictionary>} aParams array of parameters for Request class
     * @example
     * o = new TBSRequest();
     * o.setRequestListByParam([
     *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg:},
     *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"}
     * ]);
     */
	setRequestListByParam(aParams) {
		/** @type {Array<Request>} */ let a = [];
		for (let i = 0; i < aParams.length; i++) {
			let dReq = new Request(aParams[0]);
			a.push(dReq);
		}
		this.dRequestList = a;
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let a = [];

		// 1. version
		if (this.version !== 0)
			throw "not supported version: " + this.version;

		// 2. requestorName
		if (this.dRequestorName !== null)
			throw "requestorName not supported";

		// 3. requestList
		let seqRequestList =
			new DERSequence({ array: this.dRequestList });
		a.push(seqRequestList);

		// 4. requestExtensions
		if (this.dRequestExt !== null)
			throw "requestExtensions not supported";

		// 5. construct SEQUENCE
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * ASN.1 OCSPRequest class for OCSP<br/>
 * @description
 * OCSPRequest ASN.1 class is defined in 
 * <a href="https://tools.ietf.org/html/rfc6960#section-4.1.1">RFC 6960 4.1.1</a>. 
 * A signed request is not supported yet in this version.
 * <pre>
 * OCSPRequest ::= SEQUENCE {
 *   tbsRequest             TBSRequest,
 *   optionalSignature  [0] EXPLICIT Signature OPTIONAL }
 * </pre>
 * @example
 * // default constructor
 * o = new OCSPRequest();
 * // constructor with requestList parameter
 * o = new OCSPRequest({reqList:[
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg:},
 *   {issuerCert: "-----BEGIN...", subjectCert: "-----BEGIN...", alg: "sha256"}
 * ]});
 */
export class OCSPRequest extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		/** @type {TBSRequest | null} */ this.dTbsRequest = null;
		/** @type {null} */ this.dOptionalSignature = null;

		if (params !== undefined) {
			if (params['reqList'] !== undefined) {
				let o = new TBSRequest(params);
				this.dTbsRequest = o;
			}
		}	
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let a = [];

		// 1. tbsRequest
		if (this.dTbsRequest !== null) {
			a.push(this.dTbsRequest);
		} else {
			throw "tbsRequest not set";
		}

		// 2. optionalSignature
		if (this.dOptionalSignature !== null)
			throw "optionalSignature not supported";

		// 3. construct SEQUENCE
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * generates hexadecimal string of OCSP request<br/>
 * @param {string} issuerCert string of PEM issuer certificate
 * @param {string} subjectCert string of PEM subject certificate to be verified by OCSP
 * @param {string} algName hash algorithm name used for above arguments (ex. "sha1") DEFAULT: sha1
 * @return {string} hexadecimal string of generated OCSP request
 * @description
 * This static method generates hexadecimal string of OCSP request.
 * @example
 * // generate OCSP request using sha1 algorithnm by default.
 * hReq = getRequestHex("-----BEGIN...", "-----BEGIN...");
 */
export function getRequestHex(issuerCert, subjectCert, alg) {
	if (alg === undefined) alg = DEFAULT_HASH;
	let param = { alg: alg, issuerCert: issuerCert, subjectCert: subjectCert };
	let o = new OCSPRequest({ reqList: [param] });
	return o.getEncodedHex();
}

/**
 * parse OCSPResponse<br/>
 * @param {string} h hexadecimal string of DER OCSPResponse
 * @return {Dictionary} JSON object of parsed OCSPResponse
 * @description
 * This static method parse a hexadecimal string of DER OCSPResponse and
 * returns JSON object of its parsed result.
 * Its result has following properties:
 * <ul>
 * <li>responseStatus - integer of responseStatus</li>
 * <li>certStatus - string of certStatus (ex. good, revoked or unknown)</li>
 * <li>thisUpdate - string of thisUpdate in Zulu(ex. 20151231235959Z)</li>
 * <li>nextUpdate - string of nextUpdate in Zulu(ex. 20151231235959Z)</li>
 * </ul>
 * @example
 * info = getOCSPResponseInfo("3082...");
 */
export function getOCSPResponseInfo(h) {
	let result = /** @type {Dictionary} */ ( {} );
	try {
		let v = getVbyList(h, 0, [0], "0a");
		result.responseStatus = parseInt(v, 16);
	} catch (ex) { };
	if (result.responseStatus !== 0) return result;

	try {
		// certStatus
		let idxCertStatus = getIdxbyList(h, 0, [1, 0, 1, 0, 0, 2, 0, 1]);
		if (h.substr(idxCertStatus, 2) === "80") {
			result.certStatus = "good";
		} else if (h.substr(idxCertStatus, 2) === "a1") {
			result.certStatus = "revoked";
			result.revocationTime =
				hextoutf8(getVbyList(h, idxCertStatus, [0]));
		} else if (h.substr(idxCertStatus, 2) === "82") {
			result.certStatus = "unknown";
		}
	} catch (ex) { };

	// thisUpdate
	try {
		let idxThisUpdate = getIdxbyList(h, 0, [1, 0, 1, 0, 0, 2, 0, 2]);
		result.thisUpdate = hextoutf8(getV(h, idxThisUpdate));
	} catch (ex) { };

	// nextUpdate
	try {
		let idxEncapNextUpdate = getIdxbyList(h, 0, [1, 0, 1, 0, 0, 2, 0, 3]);
		if (h.substr(idxEncapNextUpdate, 2) === "a0") {
			result.nextUpdate =
				hextoutf8(getVbyList(h, idxEncapNextUpdate, [0]));
		}
	} catch (ex) { };

	return result;
}
