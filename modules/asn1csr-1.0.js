/*
 * asn1csr.js - ASN.1 DER encoder classes for PKCS#10 CSR
 *
 * Original work Copyright (c) 2015-2018 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { ASN1Object, DERInteger, DERBitString, DERNull, DERObjectIdentifier, DERSequence, DERSet, DERTaggedObject } from "./asn1-1.0.js"
import { AlgorithmIdentifier, X500Name, X500Extension, SubjectPublicKeyInfo } from "./asn1x509-1.0.js"
import { getTLVbyList } from "./asn1hex-1.1.js"
import { KeyObject, getKey } from "./keyutil-1.0.js"
import { Signature } from "./crypto-1.1.js"
import { Dictionary } from "./../../../include/type.js"
import { hextopem, pemtohex } from "./base64x-1.1.js"
import { hex2dn } from "./x509-1.1.js"

/**
 * ASN.1 module for CSR/PKCS#10
 * <p>
 * This module contains classes for
 * <a href="https://tools.ietf.org/html/rfc2986">RFC 2986</a>
 * certificate signing request(CSR/PKCS#10) and its utilities
 * to be issued your certificate from certification authorities.
 * <h4>PROVIDING ASN.1 STRUCTURES</h4>
 * <ul>
 * <li>{@link CertificationRequest}</li>
 * <li>{@link CertificationRequestInfo}</li>
 * </ul>
 * <h4>PROVIDING UTILITY CLASSES</h4>
 * <ul>
 * <li>{@link CSRUtil}</li>
 * </ul>
 * {@link newCSRPEM} method is very useful to
 * get your certificate signing request (CSR/PKCS#10) file.
 * </p>
 */

/**
 * ASN.1 CertificationRequest structure class
 * @description
 * <br/>
 * @example
 * csri = new CertificationRequestInfo();
 * csri.setSubjectByParam({'str': '/C=US/O=Test/CN=example.com'});
 * csri.setSubjectPublicKeyByGetKey(pubKeyObj);
 * csr = new CertificationRequest({'csrinfo': csri});
 * csr.sign("SHA256withRSA", prvKeyObj);
 * pem = csr.getPEMString();
 * 
 * // -- DEFINITION OF ASN.1 SYNTAX --
 * // CertificationRequest ::= SEQUENCE {
 * //   certificationRequestInfo CertificationRequestInfo,
 * //   signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
 * //   signature                BIT STRING }
 * //
 * // CertificationRequestInfo ::= SEQUENCE {
 * //   version       INTEGER { v1(0) } (v1,...),
 * //   subject       Name,
 * //   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 * //   attributes    [0] Attributes{{ CRIAttributes }} }
 */
export class CertificationRequest extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters (ex. {})
	 */
	constructor(params) {
		super();

		/** @type {CertificationRequestInfo | null} */ this.asn1CSRInfo = null;
		/** @type {AlgorithmIdentifier | null} */ this.asn1SignatureAlg = null;
		/** @type {DERBitString | null} */ this.asn1Sig = null;
		/** @type {string | null} */ this.hexSig = null;
		/** @type {string | KeyObject | null} */ this.prvKey = null;

		if (params !== undefined && params['csrinfo'] !== undefined) {
			this.asn1CSRInfo = params['csrinfo'];
		}
	}

    /**
     * sign CertificationRequest and set signature value internally<br/>
	 * @param {string} sigAlgName
	 * @param {string | KeyObject} prvKeyObj
     * @description
     * This method self-signs CertificateRequestInfo with a subject's
     * private key and set signature value internally.
     * <br/>
     * @example
     * csr = new CertificationRequest({'csrinfo': csri});
     * csr.sign("SHA256withRSA", prvKeyObj);
     */
	sign(sigAlgName, prvKeyObj) {
		if (this.prvKey == null) this.prvKey = prvKeyObj;

		this.asn1SignatureAlg =
			new AlgorithmIdentifier(/** @type {Dictionary} */ ( { 'name': sigAlgName } ));

		let sig = new Signature(/** @type {Dictionary} */ ( { 'alg': sigAlgName } ));
		sig.init(this.prvKey);
		sig.updateHex(this.asn1CSRInfo.getEncodedHex());
		this.hexSig = sig.sign();

		this.asn1Sig = new DERBitString(/** @type {Dictionary} */ ( { 'hex': '00' + this.hexSig } ));
		let seq = new DERSequence(/** @type {Dictionary} */ ( {
			'array': [this.asn1CSRInfo,
			this.asn1SignatureAlg,
			this.asn1Sig]
		} ));
		this.hTLV = seq.getEncodedHex();
		this.isModified = false;
	}

    /**
     * get PEM formatted certificate signing request (CSR/PKCS#10)<br/>
     * @return PEM formatted string of CSR/PKCS#10
     * @description
     * This method is to a get CSR PEM string after signed.
     * <br/>
     * @example
     * csr = new CertificationRequest({'csrinfo': csri});
     * csr.sign();
     * pem =  csr.getPEMString();
     * // pem will be following:
     * // -----BEGIN CERTIFICATE REQUEST-----
     * // MII ...snip...
     * // -----END CERTIFICATE REQUEST-----
     */
	getPEMString() {
		return hextopem(this.getEncodedHex(), "CERTIFICATE REQUEST");
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.isModified == false && this.hTLV != null) return this.hTLV;
		throw "not signed yet";
	}
}

/**
 * ASN.1 CertificationRequestInfo structure class
 * @description
 * <pre>
 * // -- DEFINITION OF ASN.1 SYNTAX --
 * // CertificationRequestInfo ::= SEQUENCE {
 * //   version       INTEGER { v1(0) } (v1,...),
 * //   subject       Name,
 * //   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 * //   attributes    [0] Attributes{{ CRIAttributes }} }
 * </pre>
 * <br/>
 * @example
 * csri = new CertificationRequestInfo();
 * csri.setSubjectByParam({'str': '/C=US/O=Test/CN=example.com'});
 * csri.setSubjectPublicKeyByGetKey(pubKeyObj);
 */
export class CertificationRequestInfo extends ASN1Object {
	constructor() {
		super();

		/** @type {Array<ASN1Object>} */ this.asn1Array = new Array();

		/** @type {DERInteger} */ this.asn1Version = new DERInteger(/** @type {Dictionary} */ ( { 'int': 0 } ));
		/** @type {X500Name | null} */ this.asn1Subject = null;
		/** @type {SubjectPublicKeyInfo | null} */ this.asn1SubjPKey = null;
		/** @type {Array<ASN1Object>} */ this.extensionsArray = new Array();
	}

	/**
	 * set subject name field by parameter
	 * @param {Dictionary} x500NameParam X500Name parameter
	 * @description
	 * @example
	 * csri.setSubjectByParam({'str': '/C=US/CN=b'});
	 */
	setSubjectByParam(x500NameParam) {
		this.asn1Subject = new X500Name(x500NameParam);
	}

	/**
	 * set subject public key info by RSA/ECDSA/DSA key parameter
	 * @param {string | KeyObject | Dictionary} keyParam public key parameter which passed to {@link getKey} argument
	 * @description
	 * @example
	 * csri.setSubjectPublicKeyByGetKeyParam(certPEMString); // or 
	 * csri.setSubjectPublicKeyByGetKeyParam(pkcs8PublicKeyPEMString); // or 
	 * csir.setSubjectPublicKeyByGetKeyParam(kjurCryptoECDSAKeyObject); // et.al.
	 */
	setSubjectPublicKeyByGetKey(keyParam) {
		let keyObj = getKey(keyParam);
		this.asn1SubjPKey = new SubjectPublicKeyInfo(keyObj);
	}

	/**
	 * append X.509v3 extension to this object by name and parameters
	 * @param {string} name name of X.509v3 Extension object
	 * @param {Dictionary} extParams parameters as argument of Extension constructor.
	 * @description
	 * @example
	 * let o = new CertificationRequestInfo();
	 * o.appendExtensionByName('BasicConstraints', {'cA':true, 'critical': true});
	 * o.appendExtensionByName('KeyUsage', {'bin':'11'});
	 * o.appendExtensionByName('CRLDistributionPoints', {uri: 'http://aaa.com/a.crl'});
	 * o.appendExtensionByName('ExtKeyUsage', {array: [{name: 'clientAuth'}]});
	 * o.appendExtensionByName('AuthorityKeyIdentifier', {kid: '1234ab..'});
	 * o.appendExtensionByName('AuthorityInfoAccess', {array: [{accessMethod:{oid:...},accessLocation:{uri:...}}]});
	 */
	appendExtensionByName(name, extParams) {
		X500Extension.appendByNameToArray(name,
			extParams,
			this.extensionsArray);
	}

	getEncodedHex() {
		this.asn1Array = new Array();

		this.asn1Array.push(this.asn1Version);
		this.asn1Array.push(this.asn1Subject);
		this.asn1Array.push(this.asn1SubjPKey);

		// extensionRequest
		if (this.extensionsArray.length > 0) {
			let extSeq = new DERSequence(/** @type {Dictionary} */ ( { 'array': this.extensionsArray } ));
			let extSet = new DERSet(/** @type {Dictionary} */ ( { 'array': [extSeq] } ));
			let extSeq2 = new DERSequence(/** @type {Dictionary} */ ( {
				'array': [
					new DERObjectIdentifier(/** @type {Dictionary} */ ( { 'oid': "1.2.840.113549.1.9.14" } )),
					extSet
				]
			} ));
			let extTagObj = new DERTaggedObject(/** @type {Dictionary} */ ( {
				'explicit': true,
				'tag': 'a0',
				'obj': extSeq2
			} ));
			this.asn1Array.push(extTagObj);
		} else {
			let extTagObj = new DERTaggedObject(/** @type {Dictionary} */ ( {
				'explicit': false,
				'tag': 'a0',
				'obj': new DERNull()
			} ));
			this.asn1Array.push(extTagObj);
		}

		let o = new DERSequence(/** @type {Dictionary} */ ( { "array": this.asn1Array } ));
		this.hTLV = o.getEncodedHex();
		this.isModified = false;
		return this.hTLV;
	}
}

/**
 * generate a PEM format of CSR/PKCS#10 certificate signing request
 * @param {Dictionary} param parameter to generate CSR
 * @description
 * This method can generate a CSR certificate signing
 * request by a simple JSON object which has following parameters:
 * <ul>
 * <li>subject - parameter to be passed to {@link X500Name}</li>
 * <li>sbjpubkey - parameter to be passed to {@link getKey}</li>
 * <li>sigalg - signature algorithm name (ex. SHA256withRSA)</li>
 * <li>sbjprvkey - parameter to be passed to {@link getKey}</li>
 * </ul>
 *
 * @example
 * // 1) by key object
 * pem = newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: pubKeyObj,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyObj
 * });
 *
 * // 2) by private/public key PEM 
 * pem = newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: pubKeyPEM,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyPEM
 * });
 *
 * // 3) with generateKeypair
 * kp = generateKeypair("RSA", 2048);
 * pem = newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   sbjpubkey: kp.pubKeyObj,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: kp.prvKeyObj
 * });
 *
 * // 4) by private/public key PEM with extension
 * pem = newCSRPEM({
 *   subject: {str: '/C=US/O=Test/CN=example.com'},
 *   ext: [
 *     {subjectAltName: {array: [{dns: 'example.net'}]}
 *   ],
 *   sbjpubkey: pubKeyPEM,
 *   sigalg: "SHA256withRSA",
 *   sbjprvkey: prvKeyPEM
 * });
 */
export function newCSRPEM(param) {
	if (param['subject'] === undefined) throw "parameter subject undefined";
	if (param['sbjpubkey'] === undefined) throw "parameter sbjpubkey undefined";
	if (param['sigalg'] === undefined) throw "parameter sigalg undefined";
	if (param['sbjprvkey'] === undefined) throw "parameter sbjpubkey undefined";

	let csri = new CertificationRequestInfo();
	csri.setSubjectByParam(param['subject']);
	csri.setSubjectPublicKeyByGetKey(param['sbjpubkey']);

	if (param['ext'] !== undefined && param['ext'].length !== undefined) {
		for (let i = 0; i < param['ext'].length; i++) {
			for (let key in param['ext'][i]) {
				csri.appendExtensionByName(key, param['ext'][i][key]);
			}
		}
	}

	let csr = new CertificationRequest(/** @type {Dictionary} */ ( { 'csrinfo': csri } ));
	let prvKey = getKey(param['sbjprvkey']);
	csr.sign(param['sigalg'], prvKey);

	let pem = csr.getPEMString();
	return pem;
}

/**
 * get field values from CSR/PKCS#10 PEM string<br/>
 * @param {string} sPEM PEM string of CSR/PKCS#10
 * @returns {Dictionary} JSON object with parsed parameters such as name or public key
 * @description
 * This method parses PEM CSR/PKCS#1 string and retrieves
 * subject name and public key. Following parameters are available in the
 * resulted JSON object.
 * <ul>
 * <li>subject.name - subject name string (ex. /C=US/O=Test)</li>
 * <li>subject.hex - hexadecimal string of X.500 Name of subject</li>
 * <li>pubkey.obj - subject public key object such as RSAKeyEx, ECDSA, DSA</li>
 * <li>pubkey.hex - hexadecimal string of subject public key</li>
 * </ul>
 *
 * @example
 * o = getInfo("-----BEGIN CERTIFICATE REQUEST...");
 * console.log(o.subject.name) &rarr; "/C=US/O=Test"
 */
export function getInfo(sPEM) {
	let result = /** @type {Dictionary} */ ( {} );
	result['subject'] = /** @type {Dictionary} */ ( {} );
	result['pubkey'] = /** @type {Dictionary} */ ( {} );

	if (sPEM.indexOf("-----BEGIN CERTIFICATE REQUEST") == -1)
		throw "argument is not PEM file";

	let hex = pemtohex(sPEM, "CERTIFICATE REQUEST");

	result['subject']['hex'] = getTLVbyList(hex, 0, [0, 1]);
	result['subject']['name'] = hex2dn(result['subject']['hex']);

	result['pubkey']['hex'] = getTLVbyList(hex, 0, [0, 2]);
	result['pubkey']['obj'] = getKey(result['pubkey']['hex'], null, "pkcs8pub");

	return result;
}
