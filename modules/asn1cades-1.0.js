/*
 * asn1cades.js - ASN.1 DER encoder classes for RFC 5126 CAdES long term signature
 *
 * Original work Copyright (c) 2014-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { ASN1Object, DEROctetString, DERObjectIdentifier, DERSequence } from "./asn1-1.0.js"
import { AlgorithmIdentifier } from "./asn1x509-1.0.js"
import { hashHex } from "./crypto-1.1.js"
import { getChildIdx, getTLV, getTLVbyList, getIdxbyList, getV } from "./asn1hex-1.1.js"
import { Dictionary } from "./../../../include/type.js"
import { Attribute, IssuerAndSerialNumber, SignedData, AttributeList, SignerInfo } from "./asn1cms-1.0.js"
import { pemtohex } from "./base64x-1.1.js"

/**
 * ASN.1 module for RFC 5126 CAdES long term signature
 * <p>
 * This module provides 
 * <a href="https://tools.ietf.org/html/rfc5126">RFC 5126
 * CAdES(CMS Advanced Electronic Signature)</a> generator.
 *
 * <h4>SUPPORTED FORMATS</h4>
 * Following CAdES formats is supported by this library.
 * <ul>
 * <li>CAdES-BES - CAdES Basic Electronic Signature</li>
 * <li>CAdES-EPES - CAdES Explicit Policy-based Electronic Signature</li>
 * <li>CAdES-T - Electronic Signature with Time</li>
 * </ul>
 * </p>
 *
 * <h4>PROVIDED ATTRIBUTE CLASSES</h4>
 * <ul>
 * <li>{@link SignaturePolicyIdentifier} - for CAdES-EPES</li>
 * <li>{@link SignatureTimeStamp} - for CAdES-T</li>
 * <li>{@link CompleteCertificateRefs} - for CAdES-C(for future use)</li>
 * </ul>
 * NOTE: Currntly CAdES-C is not supported since parser can't
 * handle unsigned attribute.
 * 
 * <h4>OTHER CLASSES</h4>
 * <ul>
 * <li>{@link OtherHashAlgAndValue}</li>
 * <li>{@link OtherHash}</li>
 * <li>{@link OtherCertID}</li>
 * <li>{@link CAdESUtil} - utilities for CAdES</li>
 * </ul>
 *
 * <h4>GENERATE CAdES-BES</h4>
 * To generate CAdES-BES, {@link KJUR.asn.cades} namespace 
 * classes are not required and already {@link KJUR.asn.cms} namespace 
 * provides attributes for CAdES-BES.
 * Create {@link SignedData} with following
 * mandatory attribute in CAdES-BES:
 * <ul>
 * <li>{@link ContentType}</li>
 * <li>{@link MessageDigest}</li>
 * <li>{@link SigningCertificate} or </li>
 * <li>{@link SigningCertificateV2}</li>
 * </ul>
 * CMSUtil.newSignedData method is very useful to generate CAdES-BES.
 * <pre>
 * sd = CMSUtil.newSignedData({
 *   content: {str: "aaa"},
 *   certs: [certPEM],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {SigningCertificateV2: {array: [certPEM]}},
 *     signerCert: certPEM,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM
 *   }]
 * });
 * signedDataHex = sd.getContentInfoEncodedHex();
 * </pre>
 * NOTE: ContentType and MessageDigest signed attributes
 * are automatically added by default.
 *
 * <h4>GENERATE CAdES-BES with multiple signers</h4>
 * If you need signature by multiple signers, you can 
 * specify one or more items in 'signerInfos' property as below.
 * <pre>
 * sd = CMSUtil.newSignedData({
 *   content: {str: "aaa"},
 *   certs: [certPEM1, certPEM2],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {SigningCertificateV2: {array: [certPEM1]}},
 *     signerCert: certPEM1,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM1
 *   },{
 *     hashAlg: 'sha1',
 *     sAttr: {SigningCertificateV2: {array: [certPEM2]}},
 *     signerCert: certPEM2,
 *     sigAlg: 'SHA1withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM2
 *   }]
 * });
 * signedDataHex = sd.getContentInfoEncodedHex();
 * </pre>
 *
 * <h4>GENERATE CAdES-EPES</h4>
 * When you need a CAdES-EPES signature,
 * you just need to add 'SignaturePolicyIdentifier'
 * attribute as below.
 * <pre>
 * sd = CMSUtil.newSignedData({
 *   content: {str: "aaa"},
 *   certs: [certPEM],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {
 *       SigningCertificateV2: {array: [certPEM]},
 *       SignaturePolicyIdentifier: {
 *         oid: '1.2.3.4.5',
 *         hash: {alg: 'sha1', hash: 'b1b2b3b4b...'}
 *       },
 *     },
 *     signerCert: certPEM,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: pkcs8PrvKeyPEM
 *   }]
 * });
 * signedDataHex = sd.getContentInfoEncodedHex();
 * </pre>
 *
 * <h4>GENERATE CAdES-T</h4>
 * After a signed CAdES-BES or CAdES-EPES signature have been generated,
 * you can generate CAdES-T by adding SigningTimeStamp unsigned attribute.
 * <pre>
 * beshex = "30..."; // hex of CAdES-BES or EPES data 
 * info = CAdESUtil.parseSignedDataForAddingUnsigned(beshex);
 * // You can refer a hexadecimal string of signature value 
 * // in the first signerInfo in the CAdES-BES/EPES with a variable:
 * // 'info.si[0].sigval'. You need to get RFC 3161 TimeStampToken
 * // from a trusted time stamp authority. Otherwise you can also 
 * // get it by 'KJUR.asn1.tsp' module. We suppose that we could 
 * // get proper time stamp.
 * tsthex0 = "30..."; // hex of TimeStampToken for signerInfo[0] sigval
 * si0 = info.obj.signerInfoList[0];
 * si0.addUnsigned(new SignatureTimeStamp({tst: tsthex0});
 * esthex = info.obj.getContentInfoEncodedHex(); // CAdES-T
 * </pre>
 * </p>
 *
 * <h4>SAMPLE CODES</h4>
 * <ul>
 * <li><a href="../../tool_cades.html">demo program for CAdES-BES/EPES/T generation</a></li>
 * <li><a href="../../test/qunit-do-asn1cades.html">Unit test code for KJUR.asn1.cades package</a></li>
 * <li><a href="../../test/qunit-do-asn1tsp.html">Unit test code for KJUR.asn1.tsp package (See SimpleTSAAdaptor test)</a></li>
 * <li><a href="../../test/qunit-do-asn1cms.html">Unit test code for KJUR.asn1.cms package (See newSignedData test)</a></li>
 * </ul>
 */

/**
 * class for RFC 5126 CAdES SignaturePolicyIdentifier attribute
 * @description
 * <pre>
 * SignaturePolicyIdentifier ::= CHOICE {
 *    signaturePolicyId       SignaturePolicyId,
 *    signaturePolicyImplied  SignaturePolicyImplied } -- not used
 *
 * SignaturePolicyImplied ::= NULL
 * SignaturePolicyId ::= SEQUENCE {
 *    sigPolicyId           SigPolicyId,
 *    sigPolicyHash         SigPolicyHash,
 *    sigPolicyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                             SigPolicyQualifierInfo OPTIONAL }
 * SigPolicyId ::= OBJECT IDENTIFIER
 * SigPolicyHash ::= OtherHashAlgAndValue
 * </pre>
 * @example
 * let o = new SignaturePolicyIdentifier({
 *   oid: '1.2.3.4.5',
 *   hash: {alg: 'sha1', hash: 'a1a2a3a4...'}
 * });
 */
/*
 * id-aa-ets-sigPolicyId OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-aa(2) 15 }
 *
 * signature-policy-identifier attribute values have ASN.1 type
 * SignaturePolicyIdentifier:
 *
 * SigPolicyQualifierInfo ::= SEQUENCE {
 *    sigPolicyQualifierId  SigPolicyQualifierId,
 *    sigQualifier          ANY DEFINED BY sigPolicyQualifierId } 
 *
 * sigpolicyQualifierIds defined in the present document:
 * SigPolicyQualifierId ::= OBJECT IDENTIFIER
 * id-spq-ets-uri OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-spq(5) 1 }
 *
 * SPuri ::= IA5String
 *
 * id-spq-ets-unotice OBJECT IDENTIFIER ::= { iso(1)
 *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 *    smime(16) id-spq(5) 2 }
 *
 * SPUserNotice ::= SEQUENCE {
 *    noticeRef        NoticeReference OPTIONAL,
 *    explicitText     DisplayText OPTIONAL}
 *
 * NoticeReference ::= SEQUENCE {
 *    organization     DisplayText,
 *    noticeNumbers    SEQUENCE OF INTEGER }
 *
 * DisplayText ::= CHOICE {
 *    visibleString    VisibleString  (SIZE (1..200)),
 *    bmpString        BMPString      (SIZE (1..200)),
 *    utf8String       UTF8String     (SIZE (1..200)) }
 */
export class SignaturePolicyIdentifier extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

	    /** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.16.2.15";

		if (params !== undefined) {
			if (typeof params['oid'] == "string" &&
				typeof params['hash'] == "object") {
				let dOid = new DERObjectIdentifier(/** @type {Dictionary} */ ( { 'oid': params['oid'] } ));
				let dHash = new OtherHashAlgAndValue(params['hash']);
				let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': [dOid, dHash] } ));
				this.valueList = [seq];
			}
		}
	}
}

/**
 * class for OtherHashAlgAndValue ASN.1 object
 * @description
 * <pre>
 * OtherHashAlgAndValue ::= SEQUENCE {
 *    hashAlgorithm   AlgorithmIdentifier,
 *    hashValue       OtherHashValue }
 * OtherHashValue ::= OCTET STRING
 * </pre>
 */
export class OtherHashAlgAndValue extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		this.dAlg = null;
		this.dHash = null;

		if (params !== undefined) {
			if (typeof params['alg'] == "string" &&
				typeof params['hash'] == "string") {
				this.dAlg = new AlgorithmIdentifier(/** @type {Dictionary} */ ( { 'name': params['alg'] } ));
				this.dHash = new DEROctetString(/** @type {Dictionary} */ ( { 'hex': params['hash'] } ));
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': [this.dAlg, this.dHash] } ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for RFC 5126 CAdES SignatureTimeStamp attribute
 * @description
 * <pre>
 * id-aa-signatureTimeStampToken OBJECT IDENTIFIER ::=
 *    1.2.840.113549.1.9.16.2.14
 * SignatureTimeStampToken ::= TimeStampToken
 * </pre>
 */
export class SignatureTimeStamp extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.16.2.14";
		/** @type {string | null} */ this.tstHex = null;

		if (params !== undefined) {
			if (params['res'] !== undefined) {
				if (typeof params['res'] == "string" &&
					params['res'].match(/^[0-9A-Fa-f]+$/)) {
				} else if (params['res'] instanceof ASN1Object) {
				} else {
					throw "res param shall be ASN1Object or hex string";
				}
			}
			if (params['tst'] !== undefined) {
				if (typeof params['tst'] == "string" &&
					params['tst'].match(/^[0-9A-Fa-f]+$/)) {
					let d = new ASN1Object();
					this.tstHex = params['tst'];
					d.hTLV = this.tstHex;
					d.getEncodedHex();
					this.valueList = [d];
				} else if (params['tst'] instanceof ASN1Object) {
				} else {
					throw "tst param shall be ASN1Object or hex string";
				}
			}
		}
	}
}

/**
 * class for RFC 5126 CAdES CompleteCertificateRefs attribute
 * @description
 * <pre>
 * id-aa-ets-certificateRefs OBJECT IDENTIFIER = 
 *    1.2.840.113549.1.9.16.2.21
 * CompleteCertificateRefs ::=  SEQUENCE OF OtherCertID
 * </pre>
 * @example
 * o = new CompleteCertificateRefs([certPEM1,certPEM2]);
 */
export class CompleteCertificateRefs extends Attribute {
	/**
	 * @param {Array<Dictionary>=} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.16.2.21";

		if (params !== undefined) {
			this.setByArray(params);
		}
	}

    /**
     * set value by array
     * @param {Array<Dictionary>} a array of {@link OtherCertID} argument
     * @description
     */
	setByArray(a) {
		this.valueList = [];
		for (let i = 0; i < a.length; i++) {
			let o = new OtherCertID(a[i]);
			this.valueList.push(o);
		}
	}
}

/**
 * class for OtherCertID ASN.1 object
 * @description
 * <pre>
 * OtherCertID ::= SEQUENCE {
 *    otherCertHash    OtherHash,
 *    issuerSerial     IssuerSerial OPTIONAL }
 * </pre>
 * @example
 * o = new OtherCertID(certPEM);
 * o = new OtherCertID({cert:certPEM, hasis: false});
 */
export class OtherCertID extends ASN1Object {
	/**
	 * @param {string | Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {boolean} */ this.hasIssuerSerial = true;
		/** @type {OtherHash | null} */ this.dOtherCertHash = null;
		/** @type {IssuerAndSerialNumber | null} */ this.dIssuerSerial = null;

		if (params !== undefined) {
			if (typeof params == "string" &&
				params.indexOf("-----BEGIN ") != -1) {
				this.setByCertPEM(params);
			}
			if (typeof params == "object") {
				if (params['hasis'] === false)
					this.hasIssuerSerial = false;
				if (typeof params['cert'] == "string")
					this.setByCertPEM(params['cert']);
			}
		}
	}

    /**
     * set value by PEM string of certificate
     * @param {string} certPEM PEM string of certificate
     * @return unspecified
     * @description
     * This method will set value by a PEM string of a certificate.
     * This will add IssuerAndSerialNumber by default 
     * which depends on hasIssuerSerial flag.
     */
	setByCertPEM(certPEM) {
		this.dOtherCertHash = new OtherHash(certPEM);
		if (this.hasIssuerSerial)
			this.dIssuerSerial =
				new IssuerAndSerialNumber(certPEM);
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.hTLV != null) return this.hTLV;
		if (this.dOtherCertHash == null)
			throw "otherCertHash not set";
		let a = [this.dOtherCertHash];
		if (this.dIssuerSerial != null)
			a.push(this.dIssuerSerial);
		let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': a } ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for OtherHash ASN.1 object
 * @description
 * <pre>
 * OtherHash ::= CHOICE {
 *    sha1Hash   OtherHashValue,  -- This contains a SHA-1 hash
 *    otherHash  OtherHashAlgAndValue}
 * OtherHashValue ::= OCTET STRING
 * </pre>
 * @example
 * o = new OtherHash("1234");
 * o = new OtherHash(certPEMStr); // default alg=sha256
 * o = new OtherHash({alg: 'sha256', hash: '1234'});
 * o = new OtherHash({alg: 'sha256', cert: certPEM});
 * o = new OtherHash({cert: certPEM});
 */
export class OtherHash extends ASN1Object {
	/**
	 * @param {string | Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.alg = 'sha256';
		/** @type {DEROctetString | OtherHashAlgAndValue | null} */ this.dOtherHash = null;

		if (params !== undefined) {
			if (typeof params == "string") {
				if (params.indexOf("-----BEGIN ") != -1) {
					this.setByCertPEM(params);
				} else if (params.match(/^[0-9A-Fa-f]+$/)) {
					this.dOtherHash = new DEROctetString(/** @type {Dictionary} */ ( { 'hex': params } ));
				} else {
					throw "unsupported string value for params";
				}
			} else if (typeof params == "object") {
				if (typeof params['cert'] == "string") {
					if (typeof params['alg'] == "string")
						this.alg = params['alg'];
					this.setByCertPEM(params['cert']);
				} else {
					this.dOtherHash = new OtherHashAlgAndValue(params);
				}
			}
		}
	}

    /**
     * set value by PEM string of certificate
     * @param {string} certPEM PEM string of certificate
     * @return unspecified
     * @description
     * This method will set value by a PEM string of a certificate.
     * An algorithm used to hash certificate data will
     * be defined by 'alg' property and 'sha256' is default.
     */
	setByCertPEM(certPEM) {
		if (certPEM.indexOf("-----BEGIN ") == -1)
			throw "certPEM not to seem PEM format";
		let hex = pemtohex(certPEM);
		let hash = hashHex(hex, this.alg);
		this.dOtherHash =
			new OtherHashAlgAndValue(/** @type {Dictionary} */ ( { 'alg': this.alg, 'hash': hash } ));
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.dOtherHash == null)
			throw "OtherHash not set";
		return this.dOtherHash.getEncodedHex();
	}
}

/**
 * parse CMS SignedData to add unsigned attributes
 * @param {string} hex hexadecimal string of ContentInfo of CMS SignedData
 * @return {Dictionary} associative array of parsed data
 * @description
 * This method will parse a hexadecimal string of 
 * ContentInfo with CMS SignedData to add a attribute
 * to unsigned attributes field in a signerInfo field.
 * Parsed result will be an associative array which has
 * following properties:
 * <ul>
 * <li>version - hex of CMSVersion ASN.1 TLV</li>
 * <li>algs - hex of DigestAlgorithms ASN.1 TLV</li>
 * <li>encapcontent - hex of EncapContentInfo ASN.1 TLV</li>
 * <li>certs - hex of Certificates ASN.1 TLV</li>
 * <li>revs - hex of RevocationInfoChoices ASN.1 TLV</li>
 * <li>si[] - array of SignerInfo properties</li>
 * <li>obj - parsed SignedData object</li>
 * </ul>
 * @example
 * info = CAdESUtil.parseSignedDataForAddingUnsigned(beshex);
 * sd = info.obj;
 */
export function parseSignedDataForAddingUnsigned(hex) {
	let r = /** @type {Dictionary} */ ( {} );

	// 1. not oid signed-data then error
	if (getTLVbyList(hex, 0, [0]) != "06092a864886f70d010702")
		throw "hex is not CMS SignedData";

	let iSD = getIdxbyList(hex, 0, [1, 0]);
	let aSDChildIdx = getChildIdx(hex, iSD);
	if (aSDChildIdx.length < 4)
		throw "num of SignedData elem shall be 4 at least";

	// 2. HEXs of SignedData children
	// 2.1. SignedData.CMSVersion
	let iVersion = aSDChildIdx.shift();
	r['version'] = getTLV(hex, iVersion);

	// 2.2. SignedData.DigestAlgorithms
	let iAlgs = aSDChildIdx.shift();
	r['algs'] = getTLV(hex, iAlgs);

	// 2.3. SignedData.EncapContentInfo
	let iEncapContent = aSDChildIdx.shift();
	r['encapcontent'] = getTLV(hex, iEncapContent);

	// 2.4. [0]Certs 
	r['certs'] = null;
	r['revs'] = null;
	r['si'] = [];

	let iNext = aSDChildIdx.shift();
	if (hex.substr(iNext, 2) == "a0") {
		r['certs'] = getTLV(hex, iNext);
		iNext = aSDChildIdx.shift();
	}

	// 2.5. [1]Revs
	if (hex.substr(iNext, 2) == "a1") {
		r['revs'] = getTLV(hex, iNext);
		iNext = aSDChildIdx.shift();
	}

	// 2.6. SignerInfos
	let iSignerInfos = iNext;
	if (hex.substr(iSignerInfos, 2) != "31")
		throw "Can't find signerInfos";

	let aSIIndex = getChildIdx(hex, iSignerInfos);
	//alert(aSIIndex.join("-"));

	for (let i = 0; i < aSIIndex.length; i++) {
		let iSI = aSIIndex[i];
		let pSI = parseSignerInfoForAddingUnsigned(hex, iSI, i);
		r['si'][i] = pSI;
	}

	// x. obj(SignedData)
	let tmp = null;
	let obj = r['obj'] = new SignedData();

	tmp = new ASN1Object();
	tmp.hTLV = r['version'];
	obj.dCMSVersion = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['algs'];
	obj.dDigestAlgs = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['encapcontent'];
	obj.dEncapContentInfo = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['certs'];
	obj.dCerts = tmp;

	obj.signerInfoList = [];
	for (let i = 0; i < r['si'].length; i++) {
		obj.signerInfoList.push(r['si'][i].obj);
	}

	return r;
};

/**
 * parse SignerInfo to add unsigned attributes
 * @param {string} hex hexadecimal string of SignerInfo
 * @return {Dictionary} associative array of parsed data
 * @description
 * This method will parse a hexadecimal string of 
 * SignerInfo to add a attribute
 * to unsigned attributes field in a signerInfo field.
 * Parsed result will be an associative array which has
 * following properties:
 * <ul>
 * <li>version - hex TLV of version</li>
 * <li>si - hex TLV of SignerIdentifier</li>
 * <li>digalg - hex TLV of DigestAlgorithm</li>
 * <li>sattrs - hex TLV of SignedAttributes</li>
 * <li>sigalg - hex TLV of SignatureAlgorithm</li>
 * <li>sig - hex TLV of signature</li>
 * <li>sigval = hex V of signature</li>
 * <li>obj - parsed SignerInfo object</li>
 * </ul>
 * NOTE: Parsing of unsigned attributes will be provided in the
 * future version. That's way this version provides support
 * for CAdES-T and not for CAdES-C.
 */
export function parseSignerInfoForAddingUnsigned(hex, iSI, nth) {
	let r = /** @type {Dictionary} */ ( {} );
	let aSIChildIdx = getChildIdx(hex, iSI);
	//alert(aSIChildIdx.join("="));

	if (aSIChildIdx.length != 6)
		throw "not supported items for SignerInfo (!=6)";

	// 1. SignerInfo.CMSVersion
	let iVersion = aSIChildIdx.shift();
	r['version'] = getTLV(hex, iVersion);

	// 2. SignerIdentifier(IssuerAndSerialNumber)
	let iIdentifier = aSIChildIdx.shift();
	r['si'] = getTLV(hex, iIdentifier);

	// 3. DigestAlgorithm
	let iDigestAlg = aSIChildIdx.shift();
	r['digalg'] = getTLV(hex, iDigestAlg);

	// 4. SignedAttrs
	let iSignedAttrs = aSIChildIdx.shift();
	r['sattrs'] = getTLV(hex, iSignedAttrs);

	// 5. SigAlg
	let iSigAlg = aSIChildIdx.shift();
	r['sigalg'] = getTLV(hex, iSigAlg);

	// 6. Signature
	let iSig = aSIChildIdx.shift();
	r['sig'] = getTLV(hex, iSig);
	r['sigval'] = getV(hex, iSig);

	// 7. obj(SignerInfo)
	let tmp = null;
	r['obj'] = new SignerInfo();

	tmp = new ASN1Object();
	tmp.hTLV = r['version'];
	r['obj'].dCMSVersion = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['si'];
	r['obj'].dSignerIdentifier = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['digalg'];
	r['obj'].dDigestAlgorithm = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['sattrs'];
	r['obj'].dSignedAttrs = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['sigalg'];
	r['obj'].dSigAlg = tmp;

	tmp = new ASN1Object();
	tmp.hTLV = r['sig'];
	r['obj'].dSig = tmp;

	r['obj'].dUnsignedAttrs = new AttributeList();

	return r;
};
