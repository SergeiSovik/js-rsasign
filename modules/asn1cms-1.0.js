/*
 * asn1cms.js - ASN.1 DER encoder and verifier classes for Cryptographic Message Syntax(CMS)
 *
 * Original work Copyright (c) 2013-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { ASN1Object, DERInteger, DEROctetString, DERObjectIdentifier, DERSequence, DERSet, DERTaggedObject } from "./asn1-1.0.js"
import { isHex, pemtohex, utf8tohex, hextopem, hextoutf8 } from "./base64x-1.1.js"
import { name2obj } from "./asn1oid.js"
import { Time, AlgorithmIdentifier, X500Name, } from "./asn1x509-1.0.js"
import { hashHex, Signature } from "./crypto-1.1.js"
import { getVbyList, getTLVbyList, getIdxbyList, getChildIdx, getTLV, oidname } from "./asn1hex-1.1.js"
import { KeyObject, getKey } from "./keyutil-1.0.js"
import { Dictionary, isArrayOfStrings, isDictionary } from "./../../../include/type.js"
import { SignaturePolicyIdentifier } from "./asn1cades-1.0.js"
import { X509 } from "./x509-1.1.js"

/**
 * ASN.1 module for Cryptographic Message Syntax(CMS)
 * <p>
 * This module provides 
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652
 * Cryptographic Message Syntax (CMS)</a> SignedData generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate CMS SignedData</li>
 * <li>easily verify CMS SignedData</li>
 * <li>APIs are very similar to BouncyCastle library ASN.1 classes. So easy to learn.</li>
 * </ul>
 * 
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * <li>{@link SignedData}</li>
 * <li>{@link SignerInfo}</li>
 * <li>{@link AttributeList}</li>
 * <li>{@link ContentInfo}</li>
 * <li>{@link EncapsulatedContentInfo}</li>
 * <li>{@link IssuerAndSerialNumber}</li>
 * <li>{@link CMSUtil}</li>
 * <li>{@link Attribute}</li>
 * <li>{@link ContentType}</li>
 * <li>{@link MessageDigest}</li>
 * <li>{@link SigningTime}</li>
 * <li>{@link SigningCertificate}</li>
 * <li>{@link SigningCertificateV2}</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. 
 * This caused by a bug of jsdoc2.
 * </p>
 */

/**
 * Attribute class for base of CMS attribute
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * </pre>
 */
export class Attribute extends ASN1Object {
	constructor() {
		super();

		/** @type {string} */ this.attrTypeOid;
		/** @type {Array<ASN1Object>} */ this.valueList = []; // array of values
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let attrTypeASN1 = new DERObjectIdentifier(/** @type {Dictionary} */ ( { "oid": this.attrTypeOid } ));

		let attrValueASN1 = new DERSet(/** @type {Dictionary} */ ( { "array": this.valueList } ));
		try {
			attrValueASN1.getEncodedHex();
		} catch (ex) {
			throw "fail valueSet.getEncodedHex in Attribute(1)/" + ex;
		}

		let seq = new DERSequence(/** @type {Dictionary} */ ( { "array": [attrTypeASN1, attrValueASN1] } ));
		try {
			this.hTLV = seq.getEncodedHex();
		} catch (ex) {
			throw "failed seq.getEncodedHex in Attribute(2)/" + ex;
		}

		return this.hTLV;
	}
}

/**
 * class for CMS ContentType attribute
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * o = new ContentType({name: 'data'});
 * o = new ContentType({oid: '1.2.840.113549.1.9.16.1.4'});
 */
export class ContentType extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

    	/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.3";

		if (typeof params != "undefined") {
			let contentTypeASN1 = new DERObjectIdentifier(params);
			this.valueList = [contentTypeASN1];
		}
	}
}

/**
 * class for CMS MessageDigest attribute
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * MessageDigest ::= OCTET STRING
 * </pre>
 * @example
 * o = new MessageDigest({hex: 'a1a2a3a4...'});
 */
export class MessageDigest extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.4";

		if (params !== undefined) {
			if (params['eciObj'] instanceof EncapsulatedContentInfo &&
				typeof params['hashAlg'] === "string") {
				let dataHex = params['eciObj'].eContentValueHex;
				let hashAlg = params['hashAlg'];
				let hashValueHex = hashHex(dataHex, hashAlg);
				let dAttrValue1 = new DEROctetString(/** @type {Dictionary} */ ( { 'hex': hashValueHex } ));
				dAttrValue1.getEncodedHex();
				this.valueList = [dAttrValue1];
			} else {
				let dAttrValue1 = new DEROctetString(params);
				dAttrValue1.getEncodedHex();
				this.valueList = [dAttrValue1];
			}
		}
	}
}

/**
 * class for CMS SigningTime attribute
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * SigningTime  ::= Time
 * Time ::= CHOICE {
 *    utcTime UTCTime,
 *    generalTime GeneralizedTime }
 * </pre>
 * @example
 * o = new SigningTime(); // current time UTCTime by default
 * o = new SigningTime({type: 'gen'}); // current time GeneralizedTime
 * o = new SigningTime({str: '20140517093800Z'}); // specified GeneralizedTime
 * o = new SigningTime({str: '140517093800Z'}); // specified UTCTime
 */
export class SigningTime extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.5";

		if (params !== undefined) {
			let asn1 = new Time(params);
			try {
				asn1.getEncodedHex();
			} catch (ex) {
				throw "SigningTime.getEncodedHex() failed/" + ex;
			}
			this.valueList = [asn1];
		}
	}
}

/**
 * class for CMS SigningCertificate attribute
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * SigningCertificate ::= SEQUENCE {
 *    certs SEQUENCE OF ESSCertID,
 *    policies SEQUENCE OF PolicyInformation OPTIONAL }
 * ESSCertID ::= SEQUENCE {
 *    certHash Hash,
 *    issuerSerial IssuerSerial OPTIONAL }
 * IssuerSerial ::= SEQUENCE {
 *    issuer GeneralNames,
 *    serialNumber CertificateSerialNumber }
 * </pre>
 * @example
 * o = new SigningCertificate({'array': [certPEM]});
 */
export class SigningCertificate extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.16.2.12";

		if (params !== undefined) {
			if (typeof params['array'] == "object") {
				this.setCerts(params['array']);
			}
		}
	}

	/**
	 * @param {Array<string>} listPEM 
	 */
	setCerts(listPEM) {
        /** @type {Array<DERSequence>} */ let list = [];
		for (let i = 0; i < listPEM.length; i++) {
			let hex = pemtohex(listPEM[i]);
			let certHashHex = hashHex(hex, 'sha1');
			let dCertHash =
				new DEROctetString(/** @type {Dictionary} */ ( { 'hex': certHashHex } ));
			dCertHash.getEncodedHex();
			let dIssuerSerial =
				new IssuerAndSerialNumber(/** @type {Dictionary} */ ( { 'cert': listPEM[i] } ));
			dIssuerSerial.getEncodedHex();
			let dESSCertID =
				new DERSequence(/** @type {Dictionary} */ ( { 'array': [dCertHash, dIssuerSerial] } ));
			dESSCertID.getEncodedHex();
			list.push(dESSCertID);
		}

		let dValue = new DERSequence(/** @type {Dictionary} */ ( { 'array': list } ));
		dValue.getEncodedHex();
		this.valueList = [dValue];
	}
}

/**
 * class for CMS SigningCertificateV2 attribute
 * @description
 * <pre>
 * oid-signingCertificateV2 = 1.2.840.113549.1.9.16.2.47 
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * SigningCertificateV2 ::=  SEQUENCE {
 *    certs        SEQUENCE OF ESSCertIDv2,
 *    policies     SEQUENCE OF PolicyInformation OPTIONAL }
 * ESSCertIDv2 ::=  SEQUENCE {
 *    hashAlgorithm           AlgorithmIdentifier
 *                            DEFAULT {algorithm id-sha256},
 *    certHash                Hash,
 *    issuerSerial            IssuerSerial OPTIONAL }
 * Hash ::= OCTET STRING
 * IssuerSerial ::= SEQUENCE {
 *    issuer                  GeneralNames,
 *    serialNumber            CertificateSerialNumber }
 * </pre>
 * @example
 * // hash algorithm is sha256 by default:
 * o = new SigningCertificateV2({array: [certPEM]});
 * o = new SigningCertificateV2({array: [certPEM],
 *                                             hashAlg: 'sha512'});
 */
export class SigningCertificateV2 extends Attribute {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {string} */ this.attrTypeOid = "1.2.840.113549.1.9.16.2.47";

		if (params !== undefined) {
			if (isArrayOfStrings(params['array'])) {
				let hashAlg = "sha256"; // sha2 default
				if (typeof params['hashAlg'] == "string")
					hashAlg = params['hashAlg'];
				this.setCerts(/** @type {Array<string>} */ ( params['array'] ), hashAlg);
			}
		}
	}

	/**
	 * @param {Array<string>} listPEM 
	 * @param {string} hashAlg 
	 */
	setCerts(listPEM, hashAlg) {
		/** @type {Array<DERSequence>} */ let list = [];
		for (let i = 0; i < listPEM.length; i++) {
			let hex = pemtohex(listPEM[i]);

			/** @type {Array<ASN1Object>} */ let a = [];
			if (hashAlg !== "sha256")
				a.push(new AlgorithmIdentifier(/** @type {Dictionary} */ ( { 'name': hashAlg } )));

			let certHashHex = hashHex(hex, hashAlg);
			let dCertHash = new DEROctetString(/** @type {Dictionary} */ ( { 'hex': certHashHex } ));
			dCertHash.getEncodedHex();
			a.push(dCertHash);

			let dIssuerSerial =
				new IssuerAndSerialNumber(/** @type {Dictionary} */ ( { 'cert': listPEM[i] } ));
			dIssuerSerial.getEncodedHex();
			a.push(dIssuerSerial);

			let dESSCertIDv2 = new DERSequence(/** @type {Dictionary} */ ( { 'array': a } ));
			dESSCertIDv2.getEncodedHex();
			list.push(dESSCertIDv2);
		}

		let dValue = new DERSequence(/** @type {Dictionary} */ ( { 'array': list } ));
		dValue.getEncodedHex();
		this.valueList = [dValue];
	}
}

/**
 * class for IssuerAndSerialNumber ASN.1 structure for CMS
 * @description
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *    issuer Name,
 *    serialNumber CertificateSerialNumber }
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 * @example
 * // specify by X500Name and DERInteger
 * o = new IssuerAndSerialNumber(
 *      {issuer: {str: '/C=US/O=T1'}, serial {int: 3}});
 * // specify by PEM certificate
 * o = new IssuerAndSerialNumber({cert: certPEM});
 * o = new IssuerAndSerialNumber(certPEM); // since 1.0.3
 */
export class IssuerAndSerialNumber extends ASN1Object {
	/**
	 * @param {string | Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {X500Name | null} */ this.dIssuer = null;
		/** @type {DERInteger | null} */ this.dSerial = null;

		if (params !== undefined) {
			if (typeof params == "string" &&
				params.indexOf("-----BEGIN ") != -1) {
				this.setByCertPEM(params);
			}
			if (params['issuer'] && params['serial']) {
				if (params['issuer'] instanceof X500Name) {
					this.dIssuer = params['issuer'];
				} else {
					this.dIssuer = new X500Name(params['issuer']);
				}
				if (params['serial'] instanceof DERInteger) {
					this.dSerial = params['serial'];
				} else {
					this.dSerial = new DERInteger(params['serial']);
				}
			}
			if (typeof params['cert'] == "string") {
				this.setByCertPEM(params['cert']);
			}
		}
	}

	/**
	 * @param {string} certPEM 
	 */
	setByCertPEM(certPEM) {
		let certHex = pemtohex(certPEM);
		let x = new X509();
		x.hex = certHex;
		let issuerTLVHex = x.getIssuerHex();
		this.dIssuer = new X500Name();
		this.dIssuer.hTLV = issuerTLVHex;
		let serialVHex = x.getSerialNumberHex();
		this.dSerial = new DERInteger(/** @type {Dictionary} */ ( { 'hex': serialVHex } ));
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let seq = new DERSequence(/** @type {Dictionary} */ ( {
			"array": [this.dIssuer,
			this.dSerial]
		} ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for Attributes ASN.1 structure for CMS
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * </pre>
 * @example
 * // specify by X500Name and DERInteger
 * o = new AttributeList({sorted: false}); // ASN.1 BER unsorted SET OF
 * o = new AttributeList();  // ASN.1 DER sorted by default
 * o.clear();                              // clear list of Attributes
 * n = o.length();                         // get number of Attribute
 * o.add(new SigningTime()); // add SigningTime attribute
 * hex = o.getEncodedHex();                // get hex encoded ASN.1 data
 */
export class AttributeList extends ASN1Object {
	/**
	 * @param {Dictionary=} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {Array<Attribute>} */ this.list = new Array();
		/** @type {boolean} */ this.sortFlag = true;

		if (params !== undefined) {
			if (typeof params['sortflag'] != "undefined" &&
				params['sortflag'] == false)
				this.sortFlag = false;
		}
	}

	/**
	 * @param {Attribute} item 
	 */
	add(item) {
		this.list.push(item);
	}

	length() {
		return this.list.length;
	}

	clear() {
		this.list = new Array();
		this.hTLV = null;
		this.hV = '';
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (typeof this.hTLV == "string") return this.hTLV;
		let set = new DERSet(/** @type {Dictionary} */ ( {
			'array': this.list,
			'sortflag': this.sortFlag
		} ));
		this.hTLV = set.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData
 * @description
 * <pre>
 * SignerInfo ::= SEQUENCE {
 *    version CMSVersion,
 *    sid SignerIdentifier,
 *    digestAlgorithm DigestAlgorithmIdentifier,
 *    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *    signatureAlgorithm SignatureAlgorithmIdentifier,
 *    signature SignatureValue,
 *    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 * </pre>
 * @example
 * o = new SignerInfo();
 * o.setSignerIdentifier(certPEMstring);
 * o.dSignedAttrs.add(new ContentType({name: 'data'}));
 * o.dSignedAttrs.add(new MessageDigest({hex: 'a1b2...'}));
 * o.dSignedAttrs.add(new SigningTime());
 * o.sign(privteKeyParam, "SHA1withRSA");
 */
export class SignerInfo extends ASN1Object {
	constructor() {
		super()

		/** @type {DERInteger} */ this.dCMSVersion = new DERInteger(/** @type {Dictionary} */ ( { 'int': 1 } ));
		/** @type {IssuerAndSerialNumber | null} */ this.dSignerIdentifier = null;
		/** @type {AlgorithmIdentifier | null} */ this.dDigestAlgorithm = null;
		/** @type {AttributeList} */ this.dSignedAttrs = new AttributeList();
		/** @type {AlgorithmIdentifier | null} */ this.dSigAlg = null;
		/** @type {DEROctetString | null} */ this.dSig = null;
		/** @type {AttributeList} */ this.dUnsignedAttrs = new AttributeList();
	}

	/**
	 * @param {string} params 
	 */
	setSignerIdentifier(params) {
		if (params.indexOf("CERTIFICATE") != -1 &&
			params.indexOf("BEGIN") != -1 &&
			params.indexOf("END") != -1) {

			let certPEM = params;
			this.dSignerIdentifier =
				new IssuerAndSerialNumber(/** @type {Dictionary} */ ( { 'cert': params } ));
		}
	}

	/**
	 * set ContentType/MessageDigest/DigestAlgorithms for SignerInfo/SignedData
	 * @name setForContentAndHash
	 * @param {Dictionary} params JSON parameter to set content related field
	 * @description
	 * This method will specify following fields by a parameters:
	 * <ul>
	 * <li>add ContentType signed attribute by encapContentInfo</li>
	 * <li>add MessageDigest signed attribute by encapContentInfo and hashAlg</li>
	 * <li>add a hash algorithm used in MessageDigest to digestAlgorithms field of SignedData</li>
	 * <li>set a hash algorithm used in MessageDigest to digestAlgorithm field of SignerInfo</li>
	 * </ul>
	 * Argument 'params' is an associative array having following elements:
	 * <ul>
	 * <li>eciObj - {@link EncapsulatedContentInfo} object</li>
	 * <li>sdObj - {@link SignedData} object (Option) to set DigestAlgorithms</li>
	 * <li>hashAlg - string of hash algorithm name which is used for MessageDigest attribute</li>
	 * </ul>
	 * some of elements can be omited.
	 * @example
	 * sd = new SignedData();
	 * signerInfo.setForContentAndHash({sdObj: sd,
	 *                                  eciObj: sd.dEncapContentInfo,
	 *                                  hashAlg: 'sha256'});
	 */
	setForContentAndHash(params) {
		if (params !== undefined) {
			if (params['eciObj'] instanceof EncapsulatedContentInfo) {
				this.dSignedAttrs.add(new ContentType(/** @type {Dictionary} */ ( { 'oid': '1.2.840.113549.1.7.1' } )));
				this.dSignedAttrs.add(new MessageDigest(/** @type {Dictionary} */ ( {
					'eciObj': params['eciObj'],
					'hashAlg': params['hashAlg']
				} )));
			}
			if (params['sdObj'] !== undefined &&
				params['sdObj'] instanceof SignedData) {
				if (params['sdObj'].digestAlgNameList.join(":").indexOf(params['hashAlg']) == -1) {
					params['sdObj'].digestAlgNameList.push(params['hashAlg']);
				}
			}
			if (typeof params['hashAlg'] == "string") {
				this.dDigestAlgorithm = new AlgorithmIdentifier(/** @type {Dictionary} */ ( { 'name': params['hashAlg'] } ));
			}
		}
	}

	/**
	 * @param {string | KeyObject | Dictionary} keyParam 
	 * @param {string} sigAlg 
	 */
	sign(keyParam, sigAlg) {
		// set algorithm
		this.dSigAlg = new AlgorithmIdentifier(/** @type {Dictionary} */ ( { 'name': sigAlg } ));

		// set signature
		let data = this.dSignedAttrs.getEncodedHex();
		let prvKey = getKey(keyParam);
		let sig = new Signature(/** @type {Dictionary} */ ( { 'alg': sigAlg } ));
		sig.init(prvKey);
		sig.updateHex(data);
		let sigValHex = sig.sign();
		this.dSig = new DEROctetString(/** @type {Dictionary} */ ( { 'hex': sigValHex } ));
	};

	/**
	 * @param {Attribute} attr 
	 */
	addUnsigned(attr) {
		this.hTLV = null;
		this.dUnsignedAttrs.hTLV = null;
		this.dUnsignedAttrs.add(attr);
	};

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		//alert("sattrs.hTLV=" + this.dSignedAttrs.hTLV);
		if (this.dSignedAttrs instanceof AttributeList &&
			this.dSignedAttrs.length() == 0) {
			throw "SignedAttrs length = 0 (empty)";
		}
		let sa = new DERTaggedObject(/** @type {Dictionary} */ ( {
			'obj': this.dSignedAttrs,
			'tag': 'a0', 'explicit': false
		} ));
		let ua = null;;
		if (this.dUnsignedAttrs.length() > 0) {
			ua = new DERTaggedObject(/** @type {Dictionary} */ ( {
				'obj': this.dUnsignedAttrs,
				'tag': 'a1', 'explicit': false
			} ));
		}

		let items = [
			this.dCMSVersion,
			this.dSignerIdentifier,
			this.dDigestAlgorithm,
			sa,
			this.dSigAlg,
			this.dSig,
		];
		if (ua != null) items.push(ua);

		let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': items } ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for EncapsulatedContentInfo ASN.1 structure for CMS
 * @description
 * <pre>
 * EncapsulatedContentInfo ::= SEQUENCE {
 *    eContentType ContentType,
 *    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * o = new EncapsulatedContentInfo();
 * o.setContentType('1.2.3.4.5');     // specify eContentType by OID
 * o.setContentType('data');          // specify eContentType by name
 * o.setContentValueHex('a1a2a4...'); // specify eContent data by hex string
 * o.setContentValueStr('apple');     // specify eContent data by UTF-8 string
 * // for detached contents (i.e. data not concluded in eContent)
 * o.isDetached = true;               // false as default 
 */
export class EncapsulatedContentInfo extends ASN1Object {
	constructor() {
		super();

		/** @type {DERObjectIdentifier} */ this.dEContentType = new DERObjectIdentifier(/** @type {Dictionary} */ ( { 'name': 'data' } ));
		/** @type {DERTaggedObject | null} */ this.dEContent = null;
		/** @type {boolean} */ this.isDetached = false;
		/** @type {string | null} */ this.eContentValueHex = null;
	}

	/**
	 * @param {string} nameOrOid 
	 */
	setContentType(nameOrOid) {
		if (nameOrOid.match(/^[0-2][.][0-9.]+$/)) {
			this.dEContentType = new DERObjectIdentifier(/** @type {Dictionary} */ ( { 'oid': nameOrOid } ));
		} else {
			this.dEContentType = new DERObjectIdentifier(/** @type {Dictionary} */ ( { 'name': nameOrOid } ));
		}
	}

	/**
	 * @param {Dictionary} params 
	 */
	setContentValue(params) {
		if (typeof params['hex'] == "string") {
			this.eContentValueHex = params['hex'];
		} else if (typeof params['str'] == "string") {
			this.eContentValueHex = utf8tohex(params['str']);
		}
	}

	/**
	 * @param {string} valueHex 
	 */
	setContentValueHex(valueHex) {
		this.eContentValueHex = valueHex;
	}

	/**
	 * @param {string} valueStr 
	 */
	setContentValueStr(valueStr) {
		this.eContentValueHex = utf8tohex(valueStr);
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (typeof this.eContentValueHex != "string") {
			throw "eContentValue not yet set";
		}

		let dValue = new DEROctetString(/** @type {Dictionary} */ ( { 'hex': this.eContentValueHex } ));
		this.dEContent = new DERTaggedObject(/** @type {Dictionary} */ ( {
			'obj': dValue,
			'tag': 'a0',
			'explicit': true
		} ));

		let a = [this.dEContentType];
		if (!this.isDetached) a.push(this.dEContent);
		let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': a } ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

// - type
// - obj
/**
 * class for ContentInfo ASN.1 structure for CMS
 * @description
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *    contentType ContentType,
 *    content [0] EXPLICIT ANY DEFINED BY contentType }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * a = [new DERInteger({int: 1}),
 *      new DERInteger({int: 2})];
 * seq = new DERSequence({array: a});
 * o = new ContentInfo({type: 'data', obj: seq});
 */
export class ContentInfo extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		this.dContentType = null;
		this.dContent = null;

		if (params !== undefined) {
			if (params['type'])
				this.setContentType(params['type']);
			if (params['obj'] &&
				params['obj'] instanceof ASN1Object)
				this.dContent = params['obj'];
		}
	}

	/**
	 * @param {string} params 
	 */
	setContentType(params) {
		this.dContentType = name2obj(params);
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let dContent0 = new DERTaggedObject(/** @type {Dictionary} */ ( {
			'obj': this.dContent,
			'tag': 'a0',
			'explicit': true
		} ));
		let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': [this.dContentType, dContent0] } ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData
 *
 * @description
 * <pre>
 * SignedData ::= SEQUENCE {
 *    version CMSVersion,
 *    digestAlgorithms DigestAlgorithmIdentifiers,
 *    encapContentInfo EncapsulatedContentInfo,
 *    certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *    signerInfos SignerInfos }
 * SignerInfos ::= SET OF SignerInfo
 * CertificateSet ::= SET OF CertificateChoices
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * CertificateSet ::= SET OF CertificateChoices
 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
 * </pre>
 *
 * @example
 * sd = new SignedData();
 * sd.dEncapContentInfo.setContentValueStr("test string");
 * sd.signerInfoList[0].setForContentAndHash({sdObj: sd,
 *                                            eciObj: sd.dEncapContentInfo,
 *                                            hashAlg: 'sha256'});
 * sd.signerInfoList[0].dSignedAttrs.add(new SigningTime());
 * sd.signerInfoList[0].setSignerIdentifier(certPEM);
 * sd.signerInfoList[0].sign(prvP8PEM, "SHA256withRSA");
 * hex = sd.getContentInfoEncodedHex();
 */
export class SignedData extends ASN1Object {
	constructor() {
		super();

		/** @type {DERInteger | ASN1Object} */ this.dCMSVersion = new DERInteger(/** @type {Dictionary} */ ( { 'int': 1 } ));
		/** @type {DERSet | ASN1Object | null} */ this.dDigestAlgs = null;
		/** @type {Array<string>} */ this.digestAlgNameList = [];
		/** @type {EncapsulatedContentInfo | ASN1Object} */ this.dEncapContentInfo = new EncapsulatedContentInfo();
		/** @type {DERTaggedObject | ASN1Object | null} */ this.dCerts = null;
		/** @type {Array<ASN1Object>} */ this.certificateList = [];
		this.crlList = [];
		/** @type {Array<SignerInfo>} */ this.signerInfoList = [new SignerInfo()];
	}

	/**
	 * @param {string} certPEM 
	 */
	addCertificatesByPEM(certPEM) {
		let hex = pemtohex(certPEM);
		let o = new ASN1Object();
		o.hTLV = hex;
		this.certificateList.push(o);
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (typeof this.hTLV == "string") return this.hTLV;

		if (this.dDigestAlgs == null) {
			let digestAlgList = [];
			for (let i = 0; i < this.digestAlgNameList.length; i++) {
				let name = this.digestAlgNameList[i];
				let o = new AlgorithmIdentifier(/** @type {Dictionary} */ ( { 'name': name } ));
				digestAlgList.push(o);
			}
			this.dDigestAlgs = new DERSet(/** @type {Dictionary} */ ( { 'array': digestAlgList } ));
		}

		let a = [this.dCMSVersion,
		this.dDigestAlgs,
		this.dEncapContentInfo];

		if (this.dCerts == null) {
			if (this.certificateList.length > 0) {
				let o1 = new DERSet(/** @type {Dictionary} */ ( { 'array': this.certificateList } ));
				this.dCerts
					= new DERTaggedObject(/** @type {Dictionary} */ ( {
						'obj': o1,
						'tag': 'a0',
						'explicit': false
					} ));
			}
		}
		if (this.dCerts != null) a.push(this.dCerts);

		let dSignerInfos = new DERSet(/** @type {Dictionary} */ ( { 'array': this.signerInfoList } ));
		a.push(dSignerInfos);

		let seq = new DERSequence(/** @type {Dictionary} */ ( { 'array': a } ));
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}

	getContentInfo() {
		this.getEncodedHex();
		let ci = new ContentInfo(/** @type {Dictionary} */ ( { 'type': 'signed-data', 'obj': this } ));
		return ci;
	}

	getContentInfoEncodedHex() {
		let ci = this.getContentInfo();
		let ciHex = ci.getEncodedHex();
		return ciHex;
	}

	getPEM() {
		return hextopem(this.getContentInfoEncodedHex(), "CMS");
	}
}

/**
 * generate SignedData object specified by JSON parameters
 * @param {Dictionary} param JSON parameter to generate CMS SignedData
 * @return {SignedData} object just generated
 * @description
 * This method provides more easy way to genereate
 * CMS SignedData ASN.1 structure by JSON data.
 * @example
 * let sd = CMSUtil.newSignedData({
 *   content: {str: "jsrsasign"},
 *   certs: [certPEM],
 *   signerInfos: [{
 *     hashAlg: 'sha256',
 *     sAttr: {
 *       SigningTime: {}
 *       SigningCertificateV2: {array: [certPEM]},
 *     },
 *     signerCert: certPEM,
 *     sigAlg: 'SHA256withRSA',
 *     signerPrvKey: prvPEM
 *   }]
 * });
 */
export function newSignedData(param) {
	let sd = new SignedData();

	if (sd.dEncapContentInfo instanceof EncapsulatedContentInfo)
		sd.dEncapContentInfo.setContentValue(param['content']);

	if (isArrayOfStrings(param['certs'])) {
		for (let i = 0; i < param['certs'].length; i++) {
			sd.addCertificatesByPEM(param['certs'][i]);
		}
	}

	sd.signerInfoList = [];
	for (let i = 0; i < param['signerInfos'].length; i++) {
		let siParam = param['signerInfos'][i];
		if (!isDictionary(siParam)) continue;

		let si = new SignerInfo();
		si.setSignerIdentifier(siParam['signerCert']);

		si.setForContentAndHash(/** @type {Dictionary} */ ( {
			'sdObj': sd,
			'eciObj': sd.dEncapContentInfo,
			'hashAlg': siParam.hashAlg
		} ));

		for (let attrName in siParam['sAttr']) {
			let attrParam = siParam['sAttr'][attrName];
			if (attrName == "SigningTime") {
				let attr = new SigningTime(attrParam);
				si.dSignedAttrs.add(attr);
			}
			if (attrName == "SigningCertificate") {
				let attr = new SigningCertificate(attrParam);
				si.dSignedAttrs.add(attr);
			}
			if (attrName == "SigningCertificateV2") {
				let attr = new SigningCertificateV2(attrParam);
				si.dSignedAttrs.add(attr);
			}
			if (attrName == "SignaturePolicyIdentifier") {
				let attr = new SignaturePolicyIdentifier(attrParam);
				si.dSignedAttrs.add(attr);
			}
		}

		si.sign(siParam['signerPrvKey'], siParam['sigAlg']);
		sd.signerInfoList.push(si);
	}

	return sd;
}

/**
 * 
 * @param {string} hCMS 
 * @param {Dictionary} result 
 */
function findSignerInfos(hCMS, result) {
	let idx;
	for (let i = 3; i < 6; i++) {
		idx = getIdxbyList(hCMS, 0, [1, 0, i]);
		if (idx !== undefined) {
			let tag = hCMS.substr(idx, 2);
			if (tag === "a0") result['certsIdx'] = idx;
			if (tag === "a1") result['revinfosIdx'] = idx;
			if (tag === "31") result['signerinfosIdx'] = idx;
		}
	}
}

/**
 * @param {string} hCMS 
 * @param {Dictionary} result 
 */
function parseSignerInfos(hCMS, result) {
	let idxSignerInfos = result['signerinfosIdx'];
	if (idxSignerInfos === undefined) return;
	let idxList = getChildIdx(hCMS, idxSignerInfos);
	result['signerInfoIdxList'] = idxList;
	for (let i = 0; i < idxList.length; i++) {
		let idxSI = idxList[i];
		let info = /** @type {Dictionary} */ ( { 'idx': idxSI } );
		parseSignerInfo(hCMS, info);
		result['signerInfos'].push(info);
	};
}

/**
 * @param {string} hCMS 
 * @param {Dictionary} info 
 */
function parseSignerInfo(hCMS, info) {
	let idx = info['idx'];

	// 1. signer identifier
	info['signerid_issuer1'] = getTLVbyList(hCMS, idx, [1, 0], "30");
	info['signerid_serial1'] = getVbyList(hCMS, idx, [1, 1], "02");

	// 2. hash alg
	info['hashalg'] = oidname(getVbyList(hCMS, idx, [2, 0], "06"));

	// 3. [0] singedAtttrs
	let idxSignedAttrs = getIdxbyList(hCMS, idx, [3], "a0");
	info['idxSignedAttrs'] = idxSignedAttrs;
	parseSignedAttrs(hCMS, info, idxSignedAttrs);

	let aIdx = getChildIdx(hCMS, idx);
	let n = aIdx.length;
	if (n < 6) throw "malformed SignerInfo";

	info['sigalg'] = oidname(getVbyList(hCMS, idx, [n - 2, 0], "06"));
	info['sigval'] = getVbyList(hCMS, idx, [n - 1], "04");
	//info.sigval = getVbyList(hCMS, 0, [1, 0, 4, 0, 5], "04");
	//info.sigval = hCMS;
}

/**
 * @param {string} hCMS 
 * @param {Dictionary} info 
 * @param {number} idx 
 */
function parseSignedAttrs(hCMS, info, idx) {
	let aIdx = getChildIdx(hCMS, idx);
	info['signedAttrIdxList'] = aIdx;
	for (let i = 0; i < aIdx.length; i++) {
		let idxAttr = aIdx[i];
		let hAttrType = getVbyList(hCMS, idxAttr, [0], "06");
		let v;

		if (hAttrType === "2a864886f70d010905") { // siging time
			v = hextoutf8(getVbyList(hCMS, idxAttr, [1, 0]));
			info['saSigningTime'] = v;
		} else if (hAttrType === "2a864886f70d010904") { // message digest
			v = getVbyList(hCMS, idxAttr, [1, 0], "04");
			info['saMessageDigest'] = v;
		}
	}
}

/**
 * @param {string} hCMS 
 * @param {Dictionary} result 
 */
function parseSignedData(hCMS, result) {
	// check if signedData (1.2.840.113549.1.7.2) type
	if (getVbyList(hCMS, 0, [0], "06") !== "2a864886f70d010702") {
		return result;
	}
	result['cmsType'] = "signedData";

	// find eContent data
	result['econtent'] = getVbyList(hCMS, 0, [1, 0, 2, 1, 0]);

	// find certificates,revInfos,signerInfos index
	findSignerInfos(hCMS, result);

	result['signerInfos'] = /** @type {Array<Dictionary>} */ ( [] );
	parseSignerInfos(hCMS, result);
}

/**
 * @param {string} hCMS 
 * @param {Dictionary} result 
 */
function verify(hCMS, result) {
	let aSI = /** @type {Array<Dictionary>} */ ( result['parse']['signerInfos'] );
	let n = aSI.length;
	let isValid = true;
	for (let i = 0; i < n; i++) {
		let si = aSI[i];
		verifySignerInfo(hCMS, result, si, i);
		if (!si['isValid'])
			isValid = false;
	}
	result['isValid'] = isValid;
}

/**
 * @param {string} hCMS hexadecimal string of CMS signed data
 * @param {Dictionary} result JSON object of validation result
 * @param {Dictionary} si JSON object of signerInfo in the result above
 * @param {number} idx index of signerInfo???
 */
function findCert(hCMS, result, si, idx) {
	let certsIdx = result['parse']['certsIdx'];
	/** @type {Array<X509>} */ let aCert;

	/** @type {Array<number>} */ let aIdx;
	/** @type {X509} */ let x;
	if (result['certs'] === undefined) {
		aCert = [];
		result['certkeys'] = /** @type {Array<KeyObject>} */ ( [] );
		aIdx = getChildIdx(hCMS, certsIdx);
		for (let i = 0; i < aIdx.length; i++) {
			let hCert = getTLV(hCMS, aIdx[i]);
			x = new X509();
			x.readCertHex(hCert);
			aCert[i] = x;
			result['certkeys'][i] = x.getPublicKey();
		}
		result['certs'] = aCert;
	} else {
		aCert = result['certs'];
	}

	result['cccc'] = aCert.length;
	result['cccci'] = aIdx.length;

	for (let i = 0; i < aCert.length; i++) {
		let issuer2 = x.getIssuerHex();
		let serial2 = x.getSerialNumberHex();
		if (si['signerid_issuer1'] === issuer2 &&
			si['signerid_serial1'] === serial2) {
			si['certkey_idx'] = i;
		}
	}
}

/**
 * @param {string} hCMS 
 * @param {Dictionary} result 
 * @param {Dictionary} si 
 * @param {number} idx 
 */
function verifySignerInfo(hCMS, result, si, idx) {
	si['verifyDetail'] = /** @type {Dictionary} */ ( {} );

	let _detail = /** @type {Dictionary} */ ( si['verifyDetail'] );

	let econtent = result['parse']['econtent'];

	// verify MessageDigest signed attribute
	let hashalg = si['hashalg'];
	let saMessageDigest = si['saMessageDigest'];

	// verify messageDigest
	_detail['validMessageDigest'] = false;
	//_detail._econtent = econtent;
	//_detail._hashalg = hashalg;
	//_detail._saMD = saMessageDigest;
	if (hashHex(econtent, hashalg) === saMessageDigest)
		_detail['validMessageDigest'] = true;

	// find signing certificate
	findCert(hCMS, result, si, idx);
	//if (si.signerid_cert === undefined)
	//    throw Error("can't find signer certificate");

	// verify signature value
	_detail['validSignatureValue'] = false;
	let sigalg = si['sigalg'];
	let hSignedAttr = "31" + getTLV(hCMS, si['idxSignedAttrs']).substr(2);
	si['signedattrshex'] = hSignedAttr;
	let pubkey = result['certs'][si['certkey_idx']].getPublicKey();
	let sig = new Signature(/** @type {Dictionary} */ ( { 'alg': sigalg } ));
	sig.init(pubkey);
	sig.updateHex(hSignedAttr);
	let isValid = sig.verify(si['sigval']);
	_detail['validSignatureValue_isValid'] = isValid;
	if (isValid === true)
		_detail['validSignatureValue'] = true;

	// verify SignerInfo totally
	si['isValid'] = false;
	if (_detail['validMessageDigest'] &&
		_detail['validSignatureValue']) {
		si['isValid'] = true;
	}
}

/**
 * verify SignedData specified by JSON parameters
 *
 * @param {Dictionary} param JSON parameter to verify CMS SignedData
 * @return {Dictionary} JSON data as the result of validation
 * @description
 * This method provides validation for CMS SignedData.
 * Following parameters can be applied:
 * <ul>
 * <li>cms - hexadecimal data of DER CMS SignedData (aka. PKCS#7 or p7s)</li>
 *     to verify (OPTION)</li>
 * </ul>
 * @example
 * CMSUtil.verifySignedData({ cms: "3082058a..." }) 
 * &rarr;
 * {
 *   isValid: true,
 *   parse: ... // parsed data
 *   signerInfos: [
 *     {
 *     }
 *   ]
 * }
 */
export function verifySignedData(param) {
    if (param['cms'] === undefined &&
		!isHex(param['cms'])) {
	}

	let hCMS = param['cms'];

	let result = /** @type {Dictionary} */ ( { 'isValid': false, 'parse': {} } );
	parseSignedData(hCMS, result['parse']);

	verify(hCMS, result);

	return result;
}
