/*
 * x509.js - X509 class to read subject public key from certificate.
 *
 * Original work Copyright (c) 2010-2018 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { oidHexToInt } from "./asn1-1.0.js"
import { name2oid, oid2name, oid2atype } from "./asn1oid.js"
import { getChildIdx, getV, getTLV, getVbyList, getTLVbyList, getIdxbyList, getVidx, oidname, hextooidstr } from "./asn1hex-1.1.js"
import { pemtohex, hextoutf8, hextoip, hextoposhex, hextorstr } from "./base64x-1.1.js"
import { KeyObject, getKey } from "./keyutil-1.0.js"
import { Signature } from "./crypto-1.1.js"

/** @typedef {{
	critical: boolean,
	oid: string,
	vidx: number
}} ExtInfo */ var ExtInfo;

/** @typedef {{
	cA: (boolean | undefined),
	pathLen: (number | undefined)
}} ExtBasicConstraints */ var ExtBasicConstraints;

/** @typedef {{
	kid: (string | undefined)
}} ExtAuthorityKeyIdentifier */ var ExtAuthorityKeyIdentifier;

/** @typedef {{
	ocsp: Array<string>,
	caissuer: Array<string>
}} ExtAIAInfo */ var ExtAIAInfo;

/** @typedef {{
	id: string,
	cps: (string | undefined),
	unotice: (string | undefined)
}} ExtCertificatePolicie */ var ExtCertificatePolicie;

/**
 * hexadecimal X.509 certificate ASN.1 parser class.<br/>
 * @property {string} hex hexacedimal string for X.509 certificate.
 * @property {number} version format version (1: X509v1, 3: X509v3, otherwise: unknown) since jsrsasign 7.1.4
 * @author Kenji Urushima
 * @version 1.0.1 (08 May 2012)
 * @description
 * X509 class provides following functionality:
 * <ul>
 * <li>parse X.509 certificate ASN.1 structure</li>
 * <li>get basic fields, extensions, signature algorithms and signature values</li>
 * <li>read PEM certificate</li>
 * </ul>
 *
 * <ul>
 * <li><b>TO GET FIELDS</b>
 *   <ul>
 *   <li>serial - {@link X509#getSerialNumberHex}</li>
 *   <li>signature algorithm field - {@link X509#getSignatureAlgorithmField}</li>
 *   <li>issuer - {@link X509#getIssuerHex}</li>
 *   <li>issuer - {@link X509#getIssuerString}</li>
 *   <li>notBefore - {@link X509#getNotBefore}</li>
 *   <li>notAfter - {@link X509#getNotAfter}</li>
 *   <li>subject - {@link X509#getSubjectHex}</li>
 *   <li>subject - {@link X509#getSubjectString}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKey}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKeyHex}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKeyIdx}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getPublicKeyFromCertPEM}</li>
 *   <li>subjectPublicKeyInfo - {@link X509.getPublicKeyFromCertHex}</li>
 *   <li>subjectPublicKeyInfo - {@link X509#getPublicKeyContentIdx}</li>
 *   <li>signature algorithm - {@link X509#getSignatureAlgorithmName}</li>
 *   <li>signature value - {@link X509#getSignatureValueHex}</li>
 *   </ul>
 * </li>
 * <li><b>X509 METHODS TO GET EXTENSIONS</b>
 *   <ul>
 *   <li>basicConstraints - {@link X509#getExtBasicConstraints}</li>
 *   <li>keyUsage - {@link X509#getExtKeyUsageBin}</li>
 *   <li>keyUsage - {@link X509#getExtKeyUsageString}</li>
 *   <li>subjectKeyIdentifier - {@link X509#getExtSubjectKeyIdentifier}</li>
 *   <li>authorityKeyIdentifier - {@link X509#getExtAuthorityKeyIdentifier}</li>
 *   <li>extKeyUsage - {@link X509#getExtExtKeyUsageName}</li>
 *   <li>subjectAltName(DEPRECATED) - {@link X509#getExtSubjectAltName}</li>
 *   <li>subjectAltName2 - {@link X509#getExtSubjectAltName2}</li>
 *   <li>cRLDistributionPoints - {@link X509#getExtCRLDistributionPointsURI}</li>
 *   <li>authorityInfoAccess - {@link X509#getExtAIAInfo}</li>
 *   <li>certificatePolicies - {@link X509#getExtCertificatePolicies}</li>
 *   </ul>
 * </li>
 * <li><b>UTILITIES</b>
 *   <ul>
 *   <li>reading PEM X.509 certificate - {@link X509#readCertPEM}</li>
 *   <li>reading hexadecimal string of X.509 certificate - {@link X509#readCertHex}</li>
 *   <li>get all certificate information - {@link X509#getInfo}</li>
 *   <li>get specified extension information - {@link X509#getExtInfo}</li>
 *   <li>verify signature value - {@link X509#verifySignature}</li>
 *   </ul>
 * </li>
 * </ul>
 */
export class X509 {
	constructor() {
		/** @type {string | null} */ this.hex = null;
		this.version = 0; // version (1: X509v1, 3: X509v3, others: unspecified)
		this.foffset = 0; // field index offset (-1: for X509v1, 0: for X509v3)
		/** @type {Array<ExtInfo>} */ this.aExtInfo = null;
	}

	// ===== get basic fields from hex =====================================

    /**
     * get format version (X.509v1 or v3 certificate)<br/>
     * @return {number} 1 for X509v1, 3 for X509v3, otherwise 0
     * @description
     * This method returns a format version of X.509 certificate.
     * It returns 1 for X.509v1 certificate and 3 for v3 certificate.
     * Otherwise returns 0.
     * This method will be automatically called in
     * {@link X509#readCertPEM}. After then, you can use
     * {@link X509.version} parameter.
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * version = x.getVersion();    // 1 or 3
     * sn = x.getSerialNumberHex(); // return string like "01ad..."
     */
	getVersion() {
		if (this.hex === null || this.version !== 0) return this.version;

		// check if the first item of tbsCertificate "[0] { INTEGER 2 }"
		if (getTLVbyList(this.hex, 0, [0, 0]) !== "a003020102") {
			this.version = 1;
			this.foffset = -1;
			return 1;
		}

		this.version = 3;
		return 3;
	}

    /**
     * get hexadecimal string of serialNumber field of certificate.<br/>
     * @return {string} hexadecimal string of certificate serial number
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let sn = x.getSerialNumberHex(); // return string like "01ad..."
     */
	getSerialNumberHex() {
		return getVbyList(this.hex, 0, [0, 1 + this.foffset], "02");
	}

    /**
     * get signature algorithm name in basic field
     * @return {string} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
     * @description
     * This method will get a name of signature algorithm field of certificate:
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * algName = x.getSignatureAlgorithmField();
     */
	getSignatureAlgorithmField() {
		return oidname(getVbyList(this.hex, 0, [0, 2 + this.foffset, 0], "06"));
	}

    /**
     * get hexadecimal string of issuer field TLV of certificate.<br/>
     * @return {string} hexadecial string of issuer DN ASN.1
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let issuer = x.getIssuerHex(); // return string like "3013..."
     */
	getIssuerHex() {
		return getTLVbyList(this.hex, 0, [0, 3 + this.foffset], "30");
	}

    /**
     * get string of issuer field of certificate.<br/>
     * @return {string} issuer DN string
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let issuer = x.getIssuerString(); // return string like "/C=US/O=TEST"
     */
	getIssuerString() {
		return hex2dn(this.getIssuerHex());
	}

    /**
     * get hexadecimal string of subject field of certificate.<br/>
     * @return {string} hexadecial string of subject DN ASN.1
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let subject = x.getSubjectHex(); // return string like "3013..."
     */
	getSubjectHex() {
		return getTLVbyList(this.hex, 0, [0, 5 + this.foffset], "30");
	}

    /**
     * get string of subject field of certificate.<br/>
     * @return {string} subject DN string
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let subject = x.getSubjectString(); // return string like "/C=US/O=TEST"
     */
	getSubjectString() {
		return hex2dn(this.getSubjectHex());
	}

    /**
     * get notBefore field string of certificate.<br/>
     * @return {string} not before time value (ex. "151231235959Z")
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let notBefore = x.getNotBefore(); // return string like "151231235959Z"
     */
	getNotBefore() {
		let s = getVbyList(this.hex, 0, [0, 4 + this.foffset, 0]);
		s = s.replace(/(..)/g, "%$1");
		s = decodeURIComponent(s);
		return s;
	}

    /**
     * get notAfter field string of certificate.<br/>
     * @return {string} not after time value (ex. "151231235959Z")
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * let notAfter = x.getNotAfter(); // return string like "151231235959Z"
     */
	getNotAfter() {
		let s = getVbyList(this.hex, 0, [0, 4 + this.foffset, 1]);
		s = s.replace(/(..)/g, "%$1");
		s = decodeURIComponent(s);
		return s;
	}

    /**
     * get a hexadecimal string of subjectPublicKeyInfo field.<br/>
     * @return {string} ASN.1 SEQUENCE hexadecimal string of subjectPublicKeyInfo field
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * hSPKI = x.getPublicKeyHex(); // return string like "30820122..."
     */
	getPublicKeyHex() {
		return getTLVbyList(this.hex, 0, [0, 6 + this.foffset], "30");
	}

    /**
     * get a string index of subjectPublicKeyInfo field for hexadecimal string certificate.<br/>
     * @return {number} string index of subjectPublicKeyInfo field for hexadecimal string certificate.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * idx = x.getPublicKeyIdx(); // return string index in x.hex parameter
     */
	getPublicKeyIdx() {
		return getIdxbyList(this.hex, 0, [0, 6 + this.foffset], "30");
	}

    /**
     * get a string index of contents of subjectPublicKeyInfo BITSTRING value from hexadecimal certificate<br/>
     * @return {number} string index of key contents
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * idx = x.getPublicKeyContentIdx(); // return string index in x.hex parameter
     */
	// NOTE: Without BITSTRING encapsulation.
	getPublicKeyContentIdx() {
		let idx = this.getPublicKeyIdx();
		return getIdxbyList(this.hex, idx, [1, 0], "30");
	}

    /**
     * get a RSAKeyEx/ECDSA/DSA public key object of subjectPublicKeyInfo field.<br/>
     * @return {KeyObject} RSAKeyEx/ECDSA/DSA public key object of subjectPublicKeyInfo field
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM);
     * pubkey= x.getPublicKey();
     */
	getPublicKey() {
		return getKey(this.getPublicKeyHex(), null, "pkcs8pub");
	}

    /**
     * get signature algorithm name from hexadecimal certificate data
     * @param {string} hCert hexadecimal string of X.509 certificate binary
     * @return {string} signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
     * @description
     * This method will get signature algorithm name of certificate:
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * x.getSignatureAlgorithmName() &rarr; "SHA256withRSA"
     */
	getSignatureAlgorithmName() {
		return oidname(getVbyList(this.hex, 0, [1, 0], "06"));
	}

    /**
     * get signature value in hexadecimal string<br/>
     * @return {string} signature value hexadecimal string without BitString unused bits
     * @description
     * This method will get signature value of certificate:
     * @example
     * let x = new X509();
     * x.readCertPEM(sCertPEM);
     * x.getSignatureValueHex() &rarr "8a4c47913..."
     */
	getSignatureValueHex() {
		return getVbyList(this.hex, 0, [2], "03", true);
	}

    /**
     * verifies signature value by public key<br/>
     * @param {KeyObject} pubKey public key object
     * @return {boolean} true if signature value is valid otherwise false
     * @description
     * This method verifies signature value of hexadecimal string of 
     * X.509 certificate by specified public key object.
     * @example
     * pubKey = getKey(pemPublicKey); // or certificate
     * x = new X509();
     * x.readCertPEM(pemCert);
     * x.verifySignature(pubKey) &rarr; true, false or raising exception
     */
	verifySignature(pubKey) {
		let algName = this.getSignatureAlgorithmName();
		let hSigVal = this.getSignatureValueHex();
		let hTbsCert = getTLVbyList(this.hex, 0, [0], "30");

		let sig = new Signature({ 'alg': algName });
		sig.init(pubKey);
		sig.updateHex(hTbsCert);
		return sig.verify(hSigVal);
	}

	// ===== parse extension ======================================
    /**
     * set array of X.509v3 extesion information such as extension OID, criticality and value index.<br/>
     * @description
     * This method will set an array of X.509v3 extension information having 
     * following parameters:
     * <ul>
     * <li>oid - extension OID (ex. 2.5.29.19)</li>
     * <li>critical - true or false</li>
     * <li>vidx - string index for extension value</li>
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     *
     * x.aExtInfo &rarr;
     * [ { oid: "2.5.29,19", critical: true, vidx: 2504 }, ... ]
     */
	parseExt() {
		if (this.version !== 3) return -1;
		let iExtSeq = getIdxbyList(this.hex, 0, [0, 7, 0], "30");
		let aExtIdx = getChildIdx(this.hex, iExtSeq);

		this.aExtInfo = new Array();
		for (let i = 0; i < aExtIdx.length; i++) {
			let critical = false;
			let a = getChildIdx(this.hex, aExtIdx[i]);
			let offset = 0;

			if (a.length === 3) {
				critical = true;
				offset = 1;
			}

			let oid = hextooidstr(getVbyList(this.hex, aExtIdx[i], [0], "06"));
			let octidx = getIdxbyList(this.hex, aExtIdx[i], [1 + offset]);
			let vidx = getVidx(this.hex, octidx);
			this.aExtInfo.push({critical: critical, oid: oid, vidx: vidx});
		}
	}

    /**
     * get a X.509v3 extesion information such as extension OID, criticality and value index for specified oid or name.<br/>
     * @param {string} oidOrName X.509 extension oid or name (ex. keyUsage or 2.5.29.19)
     * @return {ExtInfo | undefined} X.509 extension information such as extension OID or value indx (see {@link X509#parseExt})
     * @description
     * This method will get an X.509v3 extension information JSON object
     * having extension OID, criticality and value idx for specified
     * extension OID or name.
     * If there is no such extension, this returns undefined.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     *
     * x.getExtInfo("keyUsage") &rarr; { oid: "2.5.29.15", critical: true, vidx: 1714 }
     * x.getExtInfo("unknownExt") &rarr; undefined
     */
	getExtInfo(oidOrName) {
		let a = this.aExtInfo;
		let oid = oidOrName;
		if (!oidOrName.match(/^[0-9.]+$/)) {
			oid = name2oid(oidOrName);
		}
		if (oid === '') return undefined;

		for (let i = 0; i < a.length; i++) {
			if (a[i].oid === oid) return a[i];
		}
		return undefined;
	}

    /**
     * get BasicConstraints extension value as object in the certificate
     * @return {ExtBasicConstraints} associative array which may have "cA" and "pathLen" parameters
     * @description
     * This method will get basic constraints extension value as object with following paramters.
     * <ul>
     * <li>cA - CA flag whether CA or not</li>
     * <li>pathLen - maximum intermediate certificate length</li>
     * </ul>
     * There are use cases for return values:
     * <ul>
     * <li>{cA:true, pathLen:3} - cA flag is true and pathLen is 3</li>
     * <li>{cA:true} - cA flag is true and no pathLen</li>
     * <li>{} - basic constraints has no value in case of end entity certificate</li>
     * <li>undefined - there is no basic constraints extension</li>
     * </ul>
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtBasicConstraints() &rarr; { cA: true, pathLen: 3 };
     */
	getExtBasicConstraints() {
		let info = this.getExtInfo("basicConstraints");
		if (info === undefined) return undefined;

		let hBC = getV(this.hex, info.vidx);
		if (hBC === '') return {};
		if (hBC === '0101ff') return { cA: true };
		if (hBC.substr(0, 8) === '0101ff02') {
			let pathLexHex = getV(hBC, 6);
			let pathLen = parseInt(pathLexHex, 16);
			return { cA: true, pathLen: pathLen };
		}
		throw "basicConstraints parse error";
	}

    /**
     * get KeyUsage extension value as binary string in the certificate<br/>
     * @return {string} binary string of key usage bits (ex. '101')
     * @description
     * This method will get key usage extension value
     * as binary string such like '101'.
     * Key usage bits definition is in the RFC 5280.
     * If there is no key usage extension in the certificate,
     * it returns empty string (i.e. '').
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtKeyUsageBin() &rarr; '101'
     * // 1 - digitalSignature
     * // 0 - nonRepudiation
     * // 1 - keyEncipherment
     */
	getExtKeyUsageBin() {
		let info = this.getExtInfo("keyUsage");
		if (info === undefined) return '';

		let hKeyUsage = getV(this.hex, info.vidx);
		if (hKeyUsage.length % 2 != 0 || hKeyUsage.length <= 2)
			throw "malformed key usage value";
		let unusedBits = parseInt(hKeyUsage.substr(0, 2));
		let bKeyUsage = parseInt(hKeyUsage.substr(2), 16).toString(2);
		return bKeyUsage.substr(0, bKeyUsage.length - unusedBits);
	}

    /**
     * get KeyUsage extension value as names in the certificate<br/>
     * @return {string} comma separated string of key usage
     * @description
     * This method will get key usage extension value
     * as comma separated string of usage names.
     * If there is no key usage extension in the certificate,
     * it returns empty string (i.e. '').
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtKeyUsageString() &rarr; "digitalSignature,keyEncipherment"
     */
	getExtKeyUsageString() {
		let bKeyUsage = this.getExtKeyUsageBin();
		/** @type {Array<string>} */ let a = new Array();
		for (let i = 0; i < bKeyUsage.length; i++) {
			if (bKeyUsage.substr(i, 1) == "1") a.push(KEYUSAGE_NAME[i]);
		}
		return a.join(",");
	}

    /**
     * get subjectKeyIdentifier value as hexadecimal string in the certificate<br/>
     * @return {string} hexadecimal string of subject key identifier or null
     * @description
     * This method will get subject key identifier extension value
     * as hexadecimal string.
     * If there is this in the certificate, it returns undefined;
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtSubjectKeyIdentifier() &rarr; "1b3347ab...";
     */
	getExtSubjectKeyIdentifier() {
		let info = this.getExtInfo("subjectKeyIdentifier");
		if (info === undefined) return undefined;

		return getV(this.hex, info.vidx);
	}

    /**
     * get authorityKeyIdentifier value as JSON object in the certificate<br/>
     * @return {ExtAuthorityKeyIdentifier} JSON object of authority key identifier or null
     * @description
     * This method will get authority key identifier extension value
     * as JSON object.
     * If there is this in the certificate, it returns undefined;
     * <br>
     * NOTE: Currently this method only supports keyIdentifier so that
     * authorityCertIssuer and authorityCertSerialNumber will not
     * be return in the JSON object.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtAuthorityKeyIdentifier() &rarr; { kid: "1234abcd..." }
     */
	getExtAuthorityKeyIdentifier() {
		let info = this.getExtInfo("authorityKeyIdentifier");
		if (info === undefined) return undefined;

		/** @type {ExtAuthorityKeyIdentifier} */ let result = {};
		let hAKID = getTLV(this.hex, info.vidx);
		let a = getChildIdx(hAKID, 0);
		for (let i = 0; i < a.length; i++) {
			if (hAKID.substr(a[i], 2) === "80")
				result.kid = getV(hAKID, a[i]);
		}
		return result;
	}

    /**
     * get extKeyUsage value as array of name string in the certificate<br/>
     * @return {Array<string>} array of extended key usage ID name or oid
     * @description
     * This method will get extended key usage extension value
     * as array of name or OID string.
     * If there is this in the certificate, it returns undefined;
     * <br>
     * NOTE: Supported extended key usage ID names are defined in
     * name2oidList parameter in asn1x509.js file.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtExtKeyUsageName() &rarr; ["serverAuth", "clientAuth", "0.1.2.3.4.5"]
     */
	getExtExtKeyUsageName() {
		let info = this.getExtInfo("extKeyUsage");
		if (info === undefined) return info;

		/** @type {Array<string>} */ let result = new Array();

		let h = getTLV(this.hex, info.vidx);
		if (h === '') return result;

		let a = getChildIdx(h, 0);
		for (let i = 0; i < a.length; i++) {
			result.push(oidname(getV(h, a[i])));
		}

		return result;
	}

    /**
     * (DEPRECATED) get subjectAltName value as array of string in the certificate
     * @return {Array<string>} array of alt names
     * @deprecated since jsrsasign 8.0.1 x509 1.1.17. Please move to {@link X509#getExtSubjectAltName2}
     * @description
     * This method will get subject alt name extension value
     * as array of name.
     * If there is this in the certificate, it returns undefined;
     * <br>
     * NOTE: Currently this method supports only dNSName so that
     * other name type such like iPAddress or generalName will not be returned.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtSubjectAltName() &rarr; ["example.com", "example.org"]
     */
	getExtSubjectAltName() {
		let a = this.getExtSubjectAltName2();
		/** @type {Array<string>} */ let result = new Array();

		for (let i = 0; i < a.length; i++) {
			if (a[i][0] === "DNS") result.push(a[i][1]);
		}
		return result;
	}

    /**
     * get subjectAltName value as array of string in the certificate
     * @return {Array<Array<string>>} array of alt name array
     * @description
     * This method will get subject alt name extension value
     * as array of type and name.
     * If there is this in the certificate, it returns undefined;
     * Type of GeneralName will be shown as following:
     * <ul>
     * <li>"MAIL" - [1]rfc822Name</li>
     * <li>"DNS"  - [2]dNSName</li>
     * <li>"DN"   - [4]directoryName</li>
     * <li>"URI"  - [6]uniformResourceIdentifier</li>
     * <li>"IP"   - [7]iPAddress</li>
     * </ul>
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtSubjectAltName2() &rarr;
     * [["DNS",  "example.com"],
     *  ["DNS",  "example.org"],
     *  ["MAIL", "foo@example.com"],
     *  ["IP",   "192.168.1.1"],
     *  ["IP",   "2001:db8::2:1"],
     *  ["DN",   "/C=US/O=TEST1"]]
     */
	getExtSubjectAltName2() {
		/** @type {string} */ let gnValueHex;
		/** @type {string} */ let gnValueStr;
		/** @type {string} */ let gnTag;
		let info = this.getExtInfo("subjectAltName");
		if (info === undefined) return undefined;

		/** @type {Array<Array<string>>} */ let result = new Array();
		let h = getTLV(this.hex, info.vidx);

		let a = getChildIdx(h, 0);
		for (let i = 0; i < a.length; i++) {
			gnTag = h.substr(a[i], 2);
			gnValueHex = getV(h, a[i]);

			if (gnTag === "81") { // rfc822Name [1]
				gnValueStr = hextoutf8(gnValueHex);
				result.push(["MAIL", gnValueStr]);
			}
			if (gnTag === "82") { // dNSName [2]
				gnValueStr = hextoutf8(gnValueHex);
				result.push(["DNS", gnValueStr]);
			}
			if (gnTag === "84") { // directoryName [4]
				gnValueStr = X509.hex2dn(gnValueHex, 0);
				result.push(["DN", gnValueStr]);
			}
			if (gnTag === "86") { // uniformResourceIdentifier [6]
				gnValueStr = hextoutf8(gnValueHex);
				result.push(["URI", gnValueStr]);
			}
			if (gnTag === "87") { // iPAddress [7]
				gnValueStr = hextoip(gnValueHex);
				result.push(["IP", gnValueStr]);
			}
		}
		return result;
	}

    /**
     * get array of string for fullName URIs in cRLDistributionPoints(CDP) in the certificate
     * @return {Array<string>} array of fullName URIs of CDP of the certificate
     * @description
     * This method will get all fullName URIs of cRLDistributionPoints extension
     * in the certificate as array of URI string.
     * If there is this in the certificate, it returns undefined;
     * <br>
     * NOTE: Currently this method supports only fullName URI so that
     * other parameters will not be returned.
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtCRLDistributionPointsURI() &rarr;
     * ["http://example.com/aaa.crl", "http://example.org/aaa.crl"]
     */
	getExtCRLDistributionPointsURI() {
		let info = this.getExtInfo("cRLDistributionPoints");
		if (info === undefined) return undefined;

		/** @type {Array<string>} */ let result = new Array();
		let a = getChildIdx(this.hex, info.vidx);
		for (let i = 0; i < a.length; i++) {
			try {
				let hURI = getVbyList(this.hex, a[i], [0, 0, 0], "86");
				let uri = hextoutf8(hURI);
				result.push(uri);
			} catch (ex) { };
		}

		return result;
	}

    /**
     * get AuthorityInfoAccess extension value in the certificate as associative array
     * @return {ExtAIAInfo} associative array of AIA extension properties
     * @description
     * This method will get authority info access value
     * as associate array which has following properties:
     * <ul>
     * <li>ocsp - array of string for OCSP responder URL</li>
     * <li>caissuer - array of string for caIssuer value (i.e. CA certificates URL)</li>
     * </ul>
     * If there is this in the certificate, it returns undefined;
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtAIAInfo(hCert) &rarr; 
     * { ocsp:     ["http://ocsp.foo.com"],
     *   caissuer: ["http://rep.foo.com/aaa.p8m"] }
     */
	getExtAIAInfo() {
		let info = this.getExtInfo("authorityInfoAccess");
		if (info === undefined) return undefined;

		/** @type {ExtAIAInfo} */ let result = { ocsp: [], caissuer: [] };
		let a = getChildIdx(this.hex, info.vidx);
		for (let i = 0; i < a.length; i++) {
			let hOID = getVbyList(this.hex, a[i], [0], "06");
			let hName = getVbyList(this.hex, a[i], [1], "86");
			if (hOID === "2b06010505073001") {
				result.ocsp.push(hextoutf8(hName));
			}
			if (hOID === "2b06010505073002") {
				result.caissuer.push(hextoutf8(hName));
			}
		}

		return result;
	}

    /**
     * get CertificatePolicies extension value in the certificate as array
     * @return {Array<ExtCertificatePolicie>} array of PolicyInformation JSON object
     * @description
     * This method will get certificate policies value
     * as an array of JSON object which has following properties:
     * <ul>
     * <li>id - </li>
     * <li>cps - URI of certification practice statement</li>
     * <li>unotice - string of UserNotice explicitText</li>
     * </ul>
     * If there is this extension in the certificate,
     * it returns undefined;
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // parseExt() will also be called internally.
     * x.getExtCertificatePolicies &rarr; 
     * [{ id: 1.2.3.4,
     *    cps: "http://example.com/cps",
     *    unotice: "explicit text" }]
     */
	getExtCertificatePolicies() {
		let info = this.getExtInfo("certificatePolicies");
		if (info === undefined) return undefined;

		let hExt = getTLV(this.hex, info.vidx);
		/** @type {Array<ExtCertificatePolicie>} */ let result = [];

		let a = getChildIdx(hExt, 0);
		for (let i = 0; i < a.length; i++) {
			let a1 = getChildIdx(hExt, a[i]);
			/** @type {ExtCertificatePolicie} */ let policyInfo = { id: oidname(getV(hExt, a1[0])) };

			if (a1.length === 2) {
				let a2 = getChildIdx(hExt, a1[1]);

				for (let j = 0; j < a2.length; j++) {
					let hQualifierId = getVbyList(hExt, a2[j], [0], "06");

					if (hQualifierId === "2b06010505070201") { // cps
						policyInfo.cps = hextoutf8(getVbyList(hExt, a2[j], [1]));
					} else if (hQualifierId === "2b06010505070202") { // unotice
						policyInfo.unotice =
							hextoutf8(getVbyList(hExt, a2[j], [1, 0]));
					}
				}
			}

			result.push(policyInfo);
		}

		return result;
	}

	// ===== read certificate =====================================
    /**
     * read PEM formatted X.509 certificate from string.<br/>
     * @param {string} sCertPEM string for PEM formatted X.509 certificate
     * @example
     * x = new X509();
     * x.readCertPEM(sCertPEM); // read certificate
     */
	readCertPEM(sCertPEM) {
		this.readCertHex(pemtohex(sCertPEM));
	}

    /**
     * read a hexadecimal string of X.509 certificate<br/>
     * @param {string} sCertHex hexadecimal string of X.509 certificate
     * @description
     * NOTE: {@link X509#parseExt} will called internally since jsrsasign 7.2.0.
     * @example
     * x = new X509();
     * x.readCertHex("3082..."); // read certificate
     */
	readCertHex(sCertHex) {
		this.hex = sCertHex;
		this.getVersion(); // set version parameter

		try {
			getIdxbyList(this.hex, 0, [0, 7], "a3"); // has [3] v3ext
			this.parseExt();
		} catch (ex) { };
	}

    /**
     * get certificate information as string.<br/>
     * @return {string} certificate information string
     * @example
     * x = new X509();
     * x.readCertPEM(certPEM);
     * console.log(x.getInfo());
     * // this shows as following
     * Basic Fields
     *   serial number: 02ac5c266a0b409b8f0b79f2ae462577
     *   signature algorithm: SHA1withRSA
     *   issuer: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     *   notBefore: 061110000000Z
     *   notAfter: 311110000000Z
     *   subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     *   subject public key info:
     *     key algorithm: RSA
     *     n=c6cce573e6fbd4bb...
     *     e=10001
     * X509v3 Extensions:
     *   keyUsage CRITICAL:
     *     digitalSignature,keyCertSign,cRLSign
     *   basicConstraints CRITICAL:
     *     cA=true
     *   subjectKeyIdentifier :
     *     b13ec36903f8bf4701d498261a0802ef63642bc3
     *   authorityKeyIdentifier :
     *     kid=b13ec36903f8bf4701d498261a0802ef63642bc3
     * signature algorithm: SHA1withRSA
     * signature: 1c1a0697dcd79c9f...
     */
	getInfo() {
		let s = "Basic Fields\n";
		s += "  serial number: " + this.getSerialNumberHex() + "\n";
		s += "  signature algorithm: " + this.getSignatureAlgorithmField() + "\n";
		s += "  issuer: " + this.getIssuerString() + "\n";
		s += "  notBefore: " + this.getNotBefore() + "\n";
		s += "  notAfter: " + this.getNotAfter() + "\n";
		s += "  subject: " + this.getSubjectString() + "\n";
		s += "  subject public key info: " + "\n";

		// subject public key info
		let pubkey = this.getPublicKey();
		s += "    key algorithm: " + pubkey.type + "\n";

		if (pubkey.type === "RSA") {
			s += "    n=" + hextoposhex(pubkey.n.toString(16)).substr(0, 16) + "...\n";
			s += "    e=" + hextoposhex(pubkey.e.toString(16)) + "\n";
		}

		// X.509v3 Extensions
		let aExt = this.aExtInfo;

		if (aExt !== undefined && aExt !== null) {
			s += "X509v3 Extensions:\n";

			for (let i = 0; i < aExt.length; i++) {
				let info = aExt[i];

				// show extension name and critical flag
				let extName = oid2name(info.oid);
				if (extName === '') extName = info.oid;

				let critical = '';
				if (info.critical === true) critical = "CRITICAL";

				s += "  " + extName + " " + critical + ":\n";

				// show extension value if supported
				if (extName === "basicConstraints") {
					let bc = this.getExtBasicConstraints();
					if (bc.cA === undefined) {
						s += "    {}\n";
					} else {
						s += "    cA=true";
						if (bc.pathLen !== undefined)
							s += ", pathLen=" + bc.pathLen;
						s += "\n";
					}
				} else if (extName === "keyUsage") {
					s += "    " + this.getExtKeyUsageString() + "\n";
				} else if (extName === "subjectKeyIdentifier") {
					s += "    " + this.getExtSubjectKeyIdentifier() + "\n";
				} else if (extName === "authorityKeyIdentifier") {
					let akid = this.getExtAuthorityKeyIdentifier();
					if (akid.kid !== undefined)
						s += "    kid=" + akid.kid + "\n";
				} else if (extName === "extKeyUsage") {
					let eku = this.getExtExtKeyUsageName();
					s += "    " + eku.join(", ") + "\n";
				} else if (extName === "subjectAltName") {
					let san = this.getExtSubjectAltName2();
					s += "    " + san + "\n";
				} else if (extName === "cRLDistributionPoints") {
					let cdp = this.getExtCRLDistributionPointsURI();
					s += "    " + cdp + "\n";
				} else if (extName === "authorityInfoAccess") {
					let aia = this.getExtAIAInfo();
					if (aia.ocsp !== undefined)
						s += "    ocsp: " + aia.ocsp.join(",") + "\n";
					if (aia.caissuer !== undefined)
						s += "    caissuer: " + aia.caissuer.join(",") + "\n";
				} else if (extName === "certificatePolicies") {
					let aCP = this.getExtCertificatePolicies();
					for (let j = 0; j < aCP.length; j++) {
						if (aCP[j].id !== undefined)
							s += "    policy oid: " + aCP[j].id + "\n";
						if (aCP[j].cps !== undefined)
							s += "    cps: " + aCP[j].cps + "\n";
					}
				}
			}
		}

		s += "signature algorithm: " + this.getSignatureAlgorithmName() + "\n";
		s += "signature: " + this.getSignatureValueHex().substr(0, 16) + "...\n";
		return s;
	}
}

/**
 * get distinguished name string in OpenSSL online format from hexadecimal string of ASN.1 DER X.500 name<br/>
 * @param {string} hex hexadecimal string of ASN.1 DER distinguished name
 * @param {number=} idx index of hexadecimal string (DEFAULT=0)
 * @return {string} OpenSSL online format distinguished name
 * @description
 * This static method converts from a hexadecimal string of 
 * distinguished name (DN)
 * specified by 'hex' and 'idx' to OpenSSL oneline string representation (ex. /C=US/O=a).
 * @example
 * hex2dn("3031310b3...") &rarr; /C=US/O=a/CN=b2+OU=b1
 */
export function hex2dn(hex, idx) {
	if (idx === undefined) idx = 0;
	if (hex.substr(idx, 2) !== "30") throw "malformed DN";

	let a = new Array();

	let aIdx = getChildIdx(hex, idx);
	for (let i = 0; i < aIdx.length; i++) {
		a.push(hex2rdn(hex, aIdx[i]));
	}

	a = a.map(function (s) { return s.replace("/", "\\/"); });
	return "/" + a.join("/");
}

/**
 * get relative distinguished name string in OpenSSL online format from hexadecimal string of ASN.1 DER RDN<br/>
 * @param {string} hex hexadecimal string of ASN.1 DER concludes relative distinguished name
 * @param {number=} idx index of hexadecimal string (DEFAULT=0)
 * @return {string} OpenSSL online format relative distinguished name
 * @description
 * This static method converts from a hexadecimal string of 
 * relative distinguished name (RDN)
 * specified by 'hex' and 'idx' to LDAP string representation (ex. O=test+CN=test).<br/>
 * NOTE: Multi-valued RDN is supported since jsnrsasign 6.2.2 x509 1.1.10.
 * @example
 * hex2rdn("310a3008060355040a0c0161") &rarr; O=a
 * hex2rdn("31143008060355040a0c01613008060355040a0c0162") &rarr; O=a+O=b
 */
export function hex2rdn(hex, idx) {
	if (idx === undefined) idx = 0;
	if (hex.substr(idx, 2) !== "31") throw "malformed RDN";

	/** @type {Array<string>} */ let a = new Array();

	let aIdx = getChildIdx(hex, idx);
	for (let i = 0; i < aIdx.length; i++) {
		a.push(hex2attrTypeValue(hex, aIdx[i]));
	}

	a = a.map(function (s) { return s.replace("+", "\\+"); });
	return a.join("+");
}

/**
 * get string from hexadecimal string of ASN.1 DER AttributeTypeAndValue<br/>
 * @param {string} hex hexadecimal string of ASN.1 DER concludes AttributeTypeAndValue
 * @param {number=} idx index of hexadecimal string (DEFAULT=0)
 * @return {string} string representation of AttributeTypeAndValue (ex. C=US)
 * @description
 * This static method converts from a hexadecimal string of AttributeTypeAndValue
 * specified by 'hex' and 'idx' to LDAP string representation (ex. C=US).
 * @example
 * hex2attrTypeValue("3008060355040a0c0161") &rarr; O=a
 * hex2attrTypeValue("300806035504060c0161") &rarr; C=a
 * hex2attrTypeValue("...3008060355040a0c0161...", 128) &rarr; O=a
 */
export function hex2attrTypeValue(hex, idx) {
	if (idx === undefined) idx = 0;
	if (hex.substr(idx, 2) !== "30") throw "malformed attribute type and value";

	let aIdx = getChildIdx(hex, idx);
	if (aIdx.length !== 2 || hex.substr(aIdx[0], 2) !== "06")
		"malformed attribute type and value";

	let oidHex = getV(hex, aIdx[0]);
	let oidInt = oidHexToInt(oidHex);
	let atype = oid2atype(oidInt);

	let hV = getV(hex, aIdx[1]);
	let rawV = hextorstr(hV);

	return atype + "=" + rawV;
}

/**
 * get RSA/DSA/ECDSA public key object from X.509 certificate hexadecimal string<br/>
 * @param {string} h hexadecimal string of X.509 certificate for RSA/ECDSA/DSA public key
 * @return {KeyObject} returns RSAKeyEx/ECDSA/DSA object of public key
 */
export function getPublicKeyFromCertHex(h) {
	let x = new X509();
	x.readCertHex(h);
	return x.getPublicKey();
}

/**
 * get RSA/DSA/ECDSA public key object from PEM certificate string
 * @param {string} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
 * @return {KeyObject} returns RSAKeyEx/ECDSA/DSA object of public key
 * @description
 * NOTE: DSA is also supported since x509 1.1.2.
 */
export function getPublicKeyFromCertPEM(sCertPEM) {
	let x = new X509();
	x.readCertPEM(sCertPEM);
	return x.getPublicKey();
}

/** @typedef {{
	algparam: (string | null),
	keyhex: string,
	algoid: string
}} KeyInfoProp */ var KeyInfoProp;

/**
 * get public key information from PEM certificate
 * @param {string} sCertPEM string of PEM formatted certificate
 * @return {KeyInfoProp} hash of information for public key
 * @description
 * Resulted associative array has following properties:<br/>
 * <ul>
 * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
 * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
 * <li>keyhex - hexadecimal string of key in the certificate</li>
 * </ul>
 * NOTE: X509v1 certificate is also supported since x509.js 1.1.9.
 */
export function getPublicKeyInfoPropOfCertPEM(sCertPEM) {
	let x, hSPKI, pubkey;
	/** @type {string | null} */ let algparam = null;

	x = new X509();
	x.readCertPEM(sCertPEM);

	hSPKI = x.getPublicKeyHex();
	let keyhex = getVbyList(hSPKI, 0, [1], "03").substr(2);
	let algoid = getVbyList(hSPKI, 0, [0, 0], "06");

	if (algoid === "2a8648ce3d0201") { // ecPublicKey
		algparam = getVbyList(hSPKI, 0, [0, 1], "06");
	}

	return {
		algparam: algparam,
		keyhex: keyhex,
		algoid: algoid
	};
}

/* ======================================================================
 *   Specific V3 Extensions
 * ====================================================================== */

export const KEYUSAGE_NAME = [
	"digitalSignature",
	"nonRepudiation",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"keyCertSign",
	"cRLSign",
	"encipherOnly",
	"decipherOnly"
];
