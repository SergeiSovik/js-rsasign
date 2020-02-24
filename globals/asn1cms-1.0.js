/*
 * asn1cms.js - ASN.1 DER encoder and verifier classes for Cryptographic Message Syntax(CMS)
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

import { DERInteger, DEROctetString, DERObjectIdentifier, DERSequence, DERSet, DERTaggedObject } from "./asn1-1.0.js"
import { isHex } from "./base64x-1.1.js"
import { name2obj, Time, AlgorithmIdentifier, X500Name,  } from "./asn1x509-1.0.js"
import { hashHex, Signature } from "./crypto-1.1.js"
import { getVbyList, getTLVbyList, getIdxbyList, getChildIdx, getTLV, oidname } from "./asn1hex-1.1.js"
import { getKey } from "./keyutil-1.0.js"

/**
 * @fileOverview
 * @name asn1cms-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.5 (2017-Sep-15)
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's module
 * // already documented in asn1-1.0.js
 * @name KJUR
 * @namespace kjur's module
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/**
 * kjur's ASN.1 module
 * // already documented in asn1-1.0.js
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * kjur's ASN.1 class for Cryptographic Message Syntax(CMS)
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
 * <li>{@link KJUR.asn1.cms.SignedData}</li>
 * <li>{@link KJUR.asn1.cms.SignerInfo}</li>
 * <li>{@link KJUR.asn1.cms.AttributeList}</li>
 * <li>{@link KJUR.asn1.cms.ContentInfo}</li>
 * <li>{@link KJUR.asn1.cms.EncapsulatedContentInfo}</li>
 * <li>{@link KJUR.asn1.cms.IssuerAndSerialNumber}</li>
 * <li>{@link KJUR.asn1.cms.CMSUtil}</li>
 * <li>{@link KJUR.asn1.cms.Attribute}</li>
 * <li>{@link KJUR.asn1.cms.ContentType}</li>
 * <li>{@link KJUR.asn1.cms.MessageDigest}</li>
 * <li>{@link KJUR.asn1.cms.SigningTime}</li>
 * <li>{@link KJUR.asn1.cms.SigningCertificate}</li>
 * <li>{@link KJUR.asn1.cms.SigningCertificateV2}</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. 
 * This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.asn1.cms
 * @namespace
 */
if (typeof KJUR.asn1.cms == "undefined" || !KJUR.asn1.cms) KJUR.asn1.cms = {};

/**
 * Attribute class for base of CMS attribute
 * @param {Object} params dictionary of parameters
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * </pre>
 */
KJUR.asn1.cms.Attribute = function(params) {
    let valueList = [], // array of values
	KJUR = KJUR,
	KJUR.asn1 = KJUR.asn1;

    KJUR.asn1.cms.Attribute.superclass.constructor.call(this);

    this.getEncodedHex = function() {
        let attrTypeASN1, attrValueASN1, seq;
        attrTypeASN1 = new KJUR.asn1.DERObjectIdentifier({"oid": this.attrTypeOid});

        attrValueASN1 = new KJUR.asn1.DERSet({"array": this.valueList});
        try {
            attrValueASN1.getEncodedHex();
        } catch (ex) {
            throw "fail valueSet.getEncodedHex in Attribute(1)/" + ex;
        }

        seq = new KJUR.asn1.DERSequence({"array": [attrTypeASN1, attrValueASN1]});
        try {
            this.hTLV = seq.getEncodedHex();
        } catch (ex) {
            throw "failed seq.getEncodedHex in Attribute(2)/" + ex;
        }

        return this.hTLV;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.Attribute, KJUR.asn1.ASN1Object);

/**
 * class for CMS ContentType attribute
 * @param {Object} params dictionary of parameters
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * o = new KJUR.asn1.cms.ContentType({name: 'data'});
 * o = new KJUR.asn1.cms.ContentType({oid: '1.2.840.113549.1.9.16.1.4'});
 */
KJUR.asn1.cms.ContentType = function(params) {

	KJUR.asn1 = KJUR.asn1;

    KJUR.asn1.cms.ContentType.superclass.constructor.call(this);

    this.attrTypeOid = "1.2.840.113549.1.9.3";
    let contentTypeASN1 = null;

    if (typeof params != "undefined") {
        let contentTypeASN1 = new KJUR.asn1.DERObjectIdentifier(params);
        this.valueList = [contentTypeASN1];
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.ContentType, KJUR.asn1.cms.Attribute);

/**
 * class for CMS MessageDigest attribute
 * @param {Object} params dictionary of parameters
 * @description
 * <pre>
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * AttributeSetValue ::= SET OF ANY
 * MessageDigest ::= OCTET STRING
 * </pre>
 * @example
 * o = new KJUR.asn1.cms.MessageDigest({hex: 'a1a2a3a4...'});
 */
KJUR.asn1.cms.MessageDigest = function(params) {



	KJUR.asn1.cms = KJUR.asn1.cms;

    KJUR.asn1.cms.MessageDigest.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.4";

    if (params !== undefined) {
        if (params['eciObj'] instanceof KJUR.asn1.cms.EncapsulatedContentInfo &&
            typeof params['hashAlg'] === "string") {
            let dataHex = params.eciObj.eContentValueHex;
            let hashAlg = params['hashAlg'];
            let hashValueHex = hashHex(dataHex, hashAlg);
            let dAttrValue1 = new DEROctetString({hex: hashValueHex});
            dAttrValue1.getEncodedHex();
            this.valueList = [dAttrValue1];
        } else {
            let dAttrValue1 = new DEROctetString(params);
            dAttrValue1.getEncodedHex();
            this.valueList = [dAttrValue1];
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.MessageDigest, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningTime attribute
 * @param {Object} params dictionary of parameters
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
 * o = new KJUR.asn1.cms.SigningTime(); // current time UTCTime by default
 * o = new KJUR.asn1.cms.SigningTime({type: 'gen'}); // current time GeneralizedTime
 * o = new KJUR.asn1.cms.SigningTime({str: '20140517093800Z'}); // specified GeneralizedTime
 * o = new KJUR.asn1.cms.SigningTime({str: '140517093800Z'}); // specified UTCTime
 */
KJUR.asn1.cms.SigningTime = function(params) {

	KJUR.asn1 = KJUR.asn1;

    KJUR.asn1.cms.SigningTime.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.5";

    if (params !== undefined) {
        let asn1 = new Time(params);
        try {
            asn1.getEncodedHex();
        } catch (ex) {
            throw "SigningTime.getEncodedHex() failed/" + ex;
        }
        this.valueList = [asn1];
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningTime, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningCertificate attribute
 * @param {Object} params dictionary of parameters
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
 * o = new KJUR.asn1.cms.SigningCertificate({array: [certPEM]});
 */
KJUR.asn1.cms.SigningCertificate = function(params) {



	KJUR.asn1.cms = KJUR.asn1.cms,
	KJUR.crypto = KJUR.crypto;

    KJUR.asn1.cms.SigningCertificate.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.12";

    this.setCerts = function(listPEM) {
        let list = [];
        for (let i = 0; i < listPEM.length; i++) {
            let hex = pemtohex(listPEM[i]);
            let certHashHex = hashHex(hex, 'sha1');
            let dCertHash = 
		new KJUR.asn1.DEROctetString({hex: certHashHex});
            dCertHash.getEncodedHex();
            let dIssuerSerial =
                new KJUR.asn1.cms.IssuerAndSerialNumber({cert: listPEM[i]});
            dIssuerSerial.getEncodedHex();
            let dESSCertID =
                new DERSequence({array: [dCertHash, dIssuerSerial]});
            dESSCertID.getEncodedHex();
            list.push(dESSCertID);
        }

        let dValue = new DERSequence({array: list});
        dValue.getEncodedHex();
        this.valueList = [dValue];
    };

    if (params !== undefined) {
        if (typeof params['array'] == "object") {
            this.setCerts(params['array']);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningCertificate, KJUR.asn1.cms.Attribute);

/**
 * class for CMS SigningCertificateV2 attribute
 * @param {Object} params dictionary of parameters
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
 * o = new KJUR.asn1.cms.SigningCertificateV2({array: [certPEM]});
 * o = new KJUR.asn1.cms.SigningCertificateV2({array: [certPEM],
 *                                             hashAlg: 'sha512'});
 */
KJUR.asn1.cms.SigningCertificateV2 = function(params) {



	KJUR.asn1.x509 = KJUR.asn1.x509,
	KJUR.asn1.cms = KJUR.asn1.cms,
	KJUR.crypto = KJUR.crypto;

    KJUR.asn1.cms.SigningCertificateV2.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.47";

    this.setCerts = function(listPEM, hashAlg) {
        let list = [];
        for (let i = 0; i < listPEM.length; i++) {
            let hex = pemtohex(listPEM[i]);

            let a = [];
            if (hashAlg !== "sha256")
                a.push(new AlgorithmIdentifier({name: hashAlg}));

            let certHashHex = hashHex(hex, hashAlg);
            let dCertHash = new KJUR.asn1.DEROctetString({hex: certHashHex});
            dCertHash.getEncodedHex();
            a.push(dCertHash);

            let dIssuerSerial =
                new KJUR.asn1.cms.IssuerAndSerialNumber({cert: listPEM[i]});
            dIssuerSerial.getEncodedHex();
            a.push(dIssuerSerial);

            let dESSCertIDv2 = new DERSequence({array: a});
            dESSCertIDv2.getEncodedHex();
            list.push(dESSCertIDv2);
        }

        let dValue = new DERSequence({array: list});
        dValue.getEncodedHex();
        this.valueList = [dValue];
    };

    if (params !== undefined) {
        if (typeof params['array'] == "object") {
            let hashAlg = "sha256"; // sha2 default
            if (typeof params['hashAlg'] == "string") 
                hashAlg = params['hashAlg'];
            this.setCerts(params.array, hashAlg);
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningCertificateV2, KJUR.asn1.cms.Attribute);

/**
 * class for IssuerAndSerialNumber ASN.1 structure for CMS
 * @param {Object} params dictionary of parameters
 * @description
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *    issuer Name,
 *    serialNumber CertificateSerialNumber }
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 * @example
 * // specify by X500Name and DERInteger
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber(
 *      {issuer: {str: '/C=US/O=T1'}, serial {int: 3}});
 * // specify by PEM certificate
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber({cert: certPEM});
 * o = new KJUR.asn1.cms.IssuerAndSerialNumber(certPEM); // since 1.0.3
 */
KJUR.asn1.cms.IssuerAndSerialNumber = function(params) {



	KJUR.asn1.cms = KJUR.asn1.cms,
	KJUR.asn1.x509 = KJUR.asn1.x509,
	_X500Name = X500Name,
	_X509 = X509;

    KJUR.asn1.cms.IssuerAndSerialNumber.superclass.constructor.call(this);
    let dIssuer = null;
    let dSerial = null;

    /*
     */
    this.setByCertPEM = function(certPEM) {
        let certHex = pemtohex(certPEM);
        let x = new _X509();
        x.hex = certHex;
        let issuerTLVHex = x.getIssuerHex();
        this.dIssuer = new _X500Name();
        this.dIssuer.hTLV = issuerTLVHex;
        let serialVHex = x.getSerialNumberHex();
        this.dSerial = new DERInteger({hex: serialVHex});
    };

    this.getEncodedHex = function() {
        let seq = new KJUR.asn1.DERSequence({"array": [this.dIssuer,
							this.dSerial]});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params == "string" &&
            params.indexOf("-----BEGIN ") != -1) {
            this.setByCertPEM(params);
        }
        if (params['issuer'] && params['serial']) {
            if (params['issuer'] instanceof _X500Name) {
                this.dIssuer = params['issuer'];
            } else {
                this.dIssuer = new _X500Name(params['issuer']);
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
};
YAHOO.lang.extend(KJUR.asn1.cms.IssuerAndSerialNumber, KJUR.asn1.ASN1Object);

/**
 * class for Attributes ASN.1 structure for CMS
 * @param {Object} params dictionary of parameters
 * @description
 * <pre>
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *    type               OBJECT IDENTIFIER,
 *    values             AttributeSetValue }
 * </pre>
 * @example
 * // specify by X500Name and DERInteger
 * o = new KJUR.asn1.cms.AttributeList({sorted: false}); // ASN.1 BER unsorted SET OF
 * o = new KJUR.asn1.cms.AttributeList();  // ASN.1 DER sorted by default
 * o.clear();                              // clear list of Attributes
 * n = o.length();                         // get number of Attribute
 * o.add(new KJUR.asn1.cms.SigningTime()); // add SigningTime attribute
 * hex = o.getEncodedHex();                // get hex encoded ASN.1 data
 */
KJUR.asn1.cms.AttributeList = function(params) {


	KJUR.asn1.cms = KJUR.asn1.cms;

    KJUR.asn1.cms.AttributeList.superclass.constructor.call(this);
    this.list = new Array();
    this.sortFlag = true;

    this.add = function(item) {
        if (item instanceof KJUR.asn1.cms.Attribute) {
            this.list.push(item);
        }
    };

    this.length = function() {
        return this.list.length;
    };

    this.clear = function() {
        this.list = new Array();
        this.hTLV = null;
        this.hV = null;
    };

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        let set = new KJUR.asn1.DERSet({array: this.list, 
                                         sortflag: this.sortFlag});
        this.hTLV = set.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (typeof params['sortflag'] != "undefined" &&
            params['sortflag'] == false)
            this.sortFlag = false;
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.AttributeList, KJUR.asn1.ASN1Object);

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData
 * @param {Object} params dictionary of parameters
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
 * o = new KJUR.asn1.cms.SignerInfo();
 * o.setSignerIdentifier(certPEMstring);
 * o.dSignedAttrs.add(new KJUR.asn1.cms.ContentType({name: 'data'}));
 * o.dSignedAttrs.add(new KJUR.asn1.cms.MessageDigest({hex: 'a1b2...'}));
 * o.dSignedAttrs.add(new KJUR.asn1.cms.SigningTime());
 * o.sign(privteKeyParam, "SHA1withRSA");
 */
KJUR.asn1.cms.SignerInfo = function(params) {



	KJUR.asn1.cms = KJUR.asn1.cms,
	_AttributeList = KJUR.asn1.cms.AttributeList,
	_ContentType = KJUR.asn1.cms.ContentType,
	_EncapsulatedContentInfo = KJUR.asn1.cms.EncapsulatedContentInfo,
	_MessageDigest = KJUR.asn1.cms.MessageDigest,
	_SignedData = KJUR.asn1.cms.SignedData,
	KJUR.asn1.x509 = KJUR.asn1.x509,
	AlgorithmIdentifier = AlgorithmIdentifier,
	KJUR.crypto = KJUR.crypto;

    KJUR.asn1.cms.SignerInfo.superclass.constructor.call(this);

    this.dCMSVersion = new KJUR.asn1.DERInteger({'int': 1});
    this.dSignerIdentifier = null;
    this.dDigestAlgorithm = null;
    this.dSignedAttrs = new _AttributeList();
    this.dSigAlg = null;
    this.dSig = null;
    this.dUnsignedAttrs = new _AttributeList();

    this.setSignerIdentifier = function(params) {
        if (typeof params == "string" &&
            params.indexOf("CERTIFICATE") != -1 &&
            params.indexOf("BEGIN") != -1 &&
            params.indexOf("END") != -1) {

            let certPEM = params;
            this.dSignerIdentifier = 
                new KJUR.asn1.cms.IssuerAndSerialNumber({cert: params});
        }
    };

    /**
     * set ContentType/MessageDigest/DigestAlgorithms for SignerInfo/SignedData
     * @name setForContentAndHash
     * @param {Array} params JSON parameter to set content related field
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
     * <li>eciObj - {@link KJUR.asn1.cms.EncapsulatedContentInfo} object</li>
     * <li>sdObj - {@link KJUR.asn1.cms.SignedData} object (Option) to set DigestAlgorithms</li>
     * <li>hashAlg - string of hash algorithm name which is used for MessageDigest attribute</li>
     * </ul>
     * some of elements can be omited.
     * @example
     * sd = new KJUR.asn1.cms.SignedData();
     * signerInfo.setForContentAndHash({sdObj: sd,
     *                                  eciObj: sd.dEncapContentInfo,
     *                                  hashAlg: 'sha256'});
     */
    this.setForContentAndHash = function(params) {
        if (params !== undefined) {
            if (params['eciObj'] instanceof _EncapsulatedContentInfo) {
                this.dSignedAttrs.add(new _ContentType({oid: '1.2.840.113549.1.7.1'}));
                this.dSignedAttrs.add(new _MessageDigest({eciObj: params.eciObj,
                                                          hashAlg: params.hashAlg}));
            }
            if (params['sdObj'] !== undefined &&
                params['sdObj'] instanceof _SignedData) {
                if (params.sdObj.digestAlgNameList.join(":").indexOf(params['hashAlg']) == -1) {
                    params.sdObj.digestAlgNameList.push(params['hashAlg']);
                }
            }
            if (typeof params['hashAlg'] == "string") {
                this.dDigestAlgorithm = new AlgorithmIdentifier({name: params.hashAlg});
            }
        }
    };

    this.sign = function(keyParam, sigAlg) {
        // set algorithm
        this.dSigAlg = new AlgorithmIdentifier({name: sigAlg});

        // set signature
        let data = this.dSignedAttrs.getEncodedHex();
        let prvKey = getKey(keyParam);
        let sig = new Signature({'alg': sigAlg});
        sig.init(prvKey);
        sig.updateHex(data);
        let sigValHex = sig.sign();
        this.dSig = new KJUR.asn1.DEROctetString({'hex': sigValHex});
    };

    /*
     */
    this.addUnsigned = function(attr) {
        this.hTLV = null;
        this.dUnsignedAttrs.hTLV = null;
        this.dUnsignedAttrs.add(attr);
    };

    this.getEncodedHex = function() {
        //alert("sattrs.hTLV=" + this.dSignedAttrs.hTLV);
        if (this.dSignedAttrs instanceof _AttributeList &&
            this.dSignedAttrs.length() == 0) {
            throw "SignedAttrs length = 0 (empty)";
        }
        let sa = new DERTaggedObject({obj: this.dSignedAttrs,
                                       tag: 'a0', explicit: false});
        let ua = null;;
        if (this.dUnsignedAttrs.length() > 0) {
            ua = new DERTaggedObject({obj: this.dUnsignedAttrs,
                                       tag: 'a1', explicit: false});
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

        let seq = new KJUR.asn1.DERSequence({array: items});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.SignerInfo, KJUR.asn1.ASN1Object);

/**
 * class for EncapsulatedContentInfo ASN.1 structure for CMS
 * @param {Object} params dictionary of parameters
 * @description
 * <pre>
 * EncapsulatedContentInfo ::= SEQUENCE {
 *    eContentType ContentType,
 *    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @example
 * o = new KJUR.asn1.cms.EncapsulatedContentInfo();
 * o.setContentType('1.2.3.4.5');     // specify eContentType by OID
 * o.setContentType('data');          // specify eContentType by name
 * o.setContentValueHex('a1a2a4...'); // specify eContent data by hex string
 * o.setContentValueStr('apple');     // specify eContent data by UTF-8 string
 * // for detached contents (i.e. data not concluded in eContent)
 * o.isDetached = true;               // false as default 
 */
KJUR.asn1.cms.EncapsulatedContentInfo = function(params) {






	KJUR.asn1.cms = KJUR.asn1.cms;

    KJUR.asn1.cms.EncapsulatedContentInfo.superclass.constructor.call(this);

    this.dEContentType = new DERObjectIdentifier({name: 'data'});
    this.dEContent = null;
    this.isDetached = false;
    this.eContentValueHex = null;
    
    this.setContentType = function(nameOrOid) {
        if (nameOrOid.match(/^[0-2][.][0-9.]+$/)) {
            this.dEContentType = new DERObjectIdentifier({oid: nameOrOid});
        } else {
            this.dEContentType = new DERObjectIdentifier({name: nameOrOid});
        }
    };

    this.setContentValue = function(params) {
        if (params !== undefined) {
            if (typeof params['hex'] == "string") {
                this.eContentValueHex = params['hex'];
            } else if (typeof params['str'] == "string") {
                this.eContentValueHex = utf8tohex(params['str']);
            }
        }
    };

    this.setContentValueHex = function(valueHex) {
        this.eContentValueHex = valueHex;
    };

    this.setContentValueStr = function(valueStr) {
        this.eContentValueHex = utf8tohex(valueStr);
    };

    this.getEncodedHex = function() {
        if (typeof this.eContentValueHex != "string") {
            throw "eContentValue not yet set";
        }

        let dValue = new DEROctetString({hex: this.eContentValueHex});
        this.dEContent = new DERTaggedObject({obj: dValue,
                                               tag: 'a0',
                                               explicit: true});

        let a = [this.dEContentType];
        if (! this.isDetached) a.push(this.dEContent);
        let seq = new DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.EncapsulatedContentInfo, KJUR.asn1.ASN1Object);

// - type
// - obj
/**
 * class for ContentInfo ASN.1 structure for CMS
 * @param {Object} params dictionary of parameters
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
 * o = new KJUR.asn1.cms.ContentInfo({type: 'data', obj: seq});
 */
KJUR.asn1.cms.ContentInfo = function(params) {




	KJUR.asn1.x509 = KJUR.asn1.x509;

    KJUR.asn1.cms.ContentInfo.superclass.constructor.call(this);

    this.dContentType = null;
    this.dContent = null;

    this.setContentType = function(params) {
        if (typeof params == "string") {
            this.dContentType = name2obj(params);
        }
    };

    this.getEncodedHex = function() {
        let dContent0 = new DERTaggedObject({obj:      this.dContent,
					      tag:      'a0',
					      explicit: true});
        let seq = new DERSequence({array: [this.dContentType, dContent0]});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    if (params !== undefined) {
        if (params['type']) 
	    this.setContentType(params['type']);
        if (params['obj'] && 
	    params['obj'] instanceof KJUR.asn1.ASN1Object)
	    this.dContent = params['obj'];
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.ContentInfo, KJUR.asn1.ASN1Object);

/**
 * class for SignerInfo ASN.1 structure of CMS SignedData
 * @param {Object} params dictionary of parameters
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
 * sd = new KJUR.asn1.cms.SignedData();
 * sd.dEncapContentInfo.setContentValueStr("test string");
 * sd.signerInfoList[0].setForContentAndHash({sdObj: sd,
 *                                            eciObj: sd.dEncapContentInfo,
 *                                            hashAlg: 'sha256'});
 * sd.signerInfoList[0].dSignedAttrs.add(new KJUR.asn1.cms.SigningTime());
 * sd.signerInfoList[0].setSignerIdentifier(certPEM);
 * sd.signerInfoList[0].sign(prvP8PEM, "SHA256withRSA");
 * hex = sd.getContentInfoEncodedHex();
 */
KJUR.asn1.cms.SignedData = function(params) {


	_ASN1Object = KJUR.asn1.ASN1Object,




	KJUR.asn1.cms = KJUR.asn1.cms,
	_EncapsulatedContentInfo = KJUR.asn1.cms.EncapsulatedContentInfo,
	_SignerInfo = KJUR.asn1.cms.SignerInfo,
	_ContentInfo = KJUR.asn1.cms.ContentInfo,
	KJUR.asn1.x509 = KJUR.asn1.x509,
	AlgorithmIdentifier = AlgorithmIdentifier;

    KJUR.asn1.cms.SignedData.superclass.constructor.call(this);

    this.dCMSVersion = new DERInteger({'int': 1});
    this.dDigestAlgs = null;
    this.digestAlgNameList = [];
    this.dEncapContentInfo = new _EncapsulatedContentInfo();
    this.dCerts = null;
    this.certificateList = [];
    this.crlList = [];
    this.signerInfoList = [new _SignerInfo()];

    this.addCertificatesByPEM = function(certPEM) {
        let hex = pemtohex(certPEM);
        let o = new _ASN1Object();
        o.hTLV = hex;
        this.certificateList.push(o);
    };

    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") return this.hTLV;
        
        if (this.dDigestAlgs == null) {
            let digestAlgList = [];
            for (let i = 0; i < this.digestAlgNameList.length; i++) {
                let name = this.digestAlgNameList[i];
                let o = new AlgorithmIdentifier({name: name});
                digestAlgList.push(o);
            }
            this.dDigestAlgs = new DERSet({array: digestAlgList});
        }

        let a = [this.dCMSVersion,
                 this.dDigestAlgs,
                 this.dEncapContentInfo];

        if (this.dCerts == null) {
            if (this.certificateList.length > 0) {
                let o1 = new DERSet({array: this.certificateList});
                this.dCerts
                    = new DERTaggedObject({obj:      o1,
                                            tag:      'a0',
                                            explicit: false});
            }
        }
        if (this.dCerts != null) a.push(this.dCerts);
        
        let dSignerInfos = new DERSet({array: this.signerInfoList});
        a.push(dSignerInfos);

        let seq = new DERSequence({array: a});
        this.hTLV = seq.getEncodedHex();
        return this.hTLV;
    };

    this.getContentInfo = function() {
        this.getEncodedHex();
        let ci = new _ContentInfo({type: 'signed-data', obj: this});
        return ci;
    };

    this.getContentInfoEncodedHex = function() {
        let ci = this.getContentInfo();
        let ciHex = ci.getEncodedHex();
        return ciHex;
    };

    this.getPEM = function() {
        return hextopem(this.getContentInfoEncodedHex(), "CMS");
    };
};
YAHOO.lang.extend(KJUR.asn1.cms.SignedData, KJUR.asn1.ASN1Object);

/**
 * CMS utiliteis class */
KJUR.asn1.cms.CMSUtil = new function() {
};

/**
 * generate SignedData object specified by JSON parameters
 * @param {Object} param JSON parameter to generate CMS SignedData
 * @return {KJUR.asn1.cms.SignedData} object just generated
 * @description
 * This method provides more easy way to genereate
 * CMS SignedData ASN.1 structure by JSON data.
 * @example
 * let sd = KJUR.asn1.cms.CMSUtil.newSignedData({
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
KJUR.asn1.cms.CMSUtil.newSignedData = function(param) {


	KJUR.asn1.cms = KJUR.asn1.cms,
	_SignerInfo = KJUR.asn1.cms.SignerInfo,
	_SignedData = KJUR.asn1.cms.SignedData,
	_SigningTime = KJUR.asn1.cms.SigningTime,
	_SigningCertificate = KJUR.asn1.cms.SigningCertificate,
	_SigningCertificateV2 = KJUR.asn1.cms.SigningCertificateV2,
	KJUR.asn1.cades = KJUR.asn1.cades,
	_SignaturePolicyIdentifier = KJUR.asn1.cades.SignaturePolicyIdentifier;

    let sd = new _SignedData();

    sd.dEncapContentInfo.setContentValue(param.content);

    if (typeof param.certs == "object") {
        for (let i = 0; i < param.certs.length; i++) {
            sd.addCertificatesByPEM(param.certs[i]);
        }
    }
    
    sd.signerInfoList = [];
    for (let i = 0; i < param.signerInfos.length; i++) {
        let siParam = param.signerInfos[i];
        let si = new _SignerInfo();
        si.setSignerIdentifier(siParam.signerCert);

        si.setForContentAndHash({sdObj:   sd,
                                 eciObj:  sd.dEncapContentInfo,
                                 hashAlg: siParam.hashAlg});

        for (attrName in siParam.sAttr) {
            let attrParam = siParam.sAttr[attrName];
            if (attrName == "SigningTime") {
                let attr = new _SigningTime(attrParam);
                si.dSignedAttrs.add(attr);
            }
            if (attrName == "SigningCertificate") {
                let attr = new _SigningCertificate(attrParam);
                si.dSignedAttrs.add(attr);
            }
            if (attrName == "SigningCertificateV2") {
                let attr = new _SigningCertificateV2(attrParam);
                si.dSignedAttrs.add(attr);
            }
            if (attrName == "SignaturePolicyIdentifier") {
                let attr = new _SignaturePolicyIdentifier(attrParam);
                si.dSignedAttrs.add(attr);
            }
        }

        si.sign(siParam.signerPrvKey, siParam.sigAlg);
        sd.signerInfoList.push(si);
    }

    return sd;
};

/**
 * verify SignedData specified by JSON parameters
 *
 * @param {Object} param JSON parameter to verify CMS SignedData
 * @return {Object} JSON data as the result of validation
 * @description
 * This method provides validation for CMS SignedData.
 * Following parameters can be applied:
 * <ul>
 * <li>cms - hexadecimal data of DER CMS SignedData (aka. PKCS#7 or p7s)</li>
 *     to verify (OPTION)</li>
 * </ul>
 * @example
 * KJUR.asn1.cms.CMSUtil.verifySignedData({ cms: "3082058a..." }) 
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
KJUR.asn1.cms.CMSUtil.verifySignedData = function(param) {
	KJUR.asn1.cms = KJUR.asn1.cms,
	_SignerInfo = KJUR.asn1.cms.SignerInfo,
	_SignedData = KJUR.asn1.cms.SignedData,
	_SigningTime = KJUR.asn1.cms.SigningTime,
	_SigningCertificate = KJUR.asn1.cms.SigningCertificate,
	_SigningCertificateV2 = KJUR.asn1.cms.SigningCertificateV2,
	KJUR.asn1.cades = KJUR.asn1.cades,
	_SignaturePolicyIdentifier = KJUR.asn1.cades.SignaturePolicyIdentifier,

    if (param.cms === undefined &&
        ! isHex(param.cms)) {
    }

    let hCMS = param.cms;

    let _findSignerInfos = function(hCMS, result) {
	let idx;
	for (let i = 3; i < 6; i++) {
	    idx = getIdxbyList(hCMS, 0, [1, 0, i]);
	    if (idx !== undefined) {
		let tag = hCMS.substr(idx, 2);
		if (tag === "a0") result.certsIdx = idx;
		if (tag === "a1") result.revinfosIdx = idx;
		if (tag === "31") result.signerinfosIdx = idx;
	    }
	}
    };

    let _parseSignerInfos = function(hCMS, result) {
	let idxSignerInfos = result.signerinfosIdx;
	if (idxSignerInfos === undefined) return;
	let idxList = getChildIdx(hCMS, idxSignerInfos);
	result.signerInfoIdxList = idxList;
	for (let i = 0; i < idxList.length; i++) {
	    let idxSI = idxList[i];
	    let info = { idx: idxSI };
	    _parseSignerInfo(hCMS, info);
	    result.signerInfos.push(info);
	};
    };

    let _parseSignerInfo = function(hCMS, info) {
	let idx = info.idx;

	// 1. signer identifier
	info.signerid_issuer1 = getTLVbyList(hCMS, idx, [1, 0], "30");
	info.signerid_serial1 = getVbyList(hCMS, idx, [1, 1], "02");

	// 2. hash alg
	info.hashalg = oidname(getVbyList(hCMS, idx, [2, 0], "06"));

	// 3. [0] singedAtttrs
	let idxSignedAttrs = getIdxbyList(hCMS, idx, [3], "a0");
	info.idxSignedAttrs = idxSignedAttrs;
	_parseSignedAttrs(hCMS, info, idxSignedAttrs);

	let aIdx = getChildIdx(hCMS, idx);
	let n = aIdx.length;
	if (n < 6) throw "malformed SignerInfo";
	
	info.sigalg = oidname(getVbyList(hCMS, idx, [n - 2, 0], "06"));
	info.sigval = getVbyList(hCMS, idx, [n - 1], "04");
	//info.sigval = getVbyList(hCMS, 0, [1, 0, 4, 0, 5], "04");
	//info.sigval = hCMS;
    };

    let _parseSignedAttrs = function(hCMS, info, idx) {
	let aIdx = getChildIdx(hCMS, idx);
	info.signedAttrIdxList = aIdx;
	for (let i = 0; i < aIdx.length; i++) {
	    let idxAttr = aIdx[i];
	    let hAttrType = getVbyList(hCMS, idxAttr, [0], "06");
	    let v;

	    if (hAttrType === "2a864886f70d010905") { // siging time
		v = hextoutf8(getVbyList(hCMS, idxAttr, [1, 0]));
		info.saSigningTime = v;
	    } else if (hAttrType === "2a864886f70d010904") { // message digest
		v = getVbyList(hCMS, idxAttr, [1, 0], "04");
		info.saMessageDigest = v;
	    }
	}
    };

    let _parseSignedData = function(hCMS, result) {
	// check if signedData (1.2.840.113549.1.7.2) type
	if (getVbyList(hCMS, 0, [0], "06") !== "2a864886f70d010702") {
	    return result;
	}
	result.cmsType = "signedData";

	// find eContent data
	result.econtent = getVbyList(hCMS, 0, [1, 0, 2, 1, 0]);

	// find certificates,revInfos,signerInfos index
	_findSignerInfos(hCMS, result);

	result.signerInfos = [];
	_parseSignerInfos(hCMS, result);
    };

    let _verify = function(hCMS, result) {
	let aSI = result.parse.signerInfos;
	let n = aSI.length;
	let isValid = true;
	for (let i = 0; i < n; i++) {
	    let si = aSI[i];
	    _verifySignerInfo(hCMS, result, si, i);
	    if (! si.isValid)
		isValid = false;
	}
	result.isValid = isValid;
    };

    /*
     * _findCert
     * 
     * @param hCMS {string} hexadecimal string of CMS signed data
     * @param result {Object} JSON object of validation result
     * @param si {Object} JSON object of signerInfo in the result above
     * @param idx {number} index of signerInfo???
     */
    let _findCert = function(hCMS, result, si, idx) {
	let certsIdx = result.parse.certsIdx;
	let aCert;

	if (result.certs === undefined) {
	    aCert = [];
	    result.certkeys = [];
	    let aIdx = getChildIdx(hCMS, certsIdx);
	    for (let i = 0; i < aIdx.length; i++) {
		let hCert = getTLV(hCMS, aIdx[i]);
		let x = new X509();
		x.readCertHex(hCert);
		aCert[i] = x;
		result.certkeys[i] = x.getPublicKey();
	    }
	    result.certs = aCert;
	} else {
	    aCert = result.certs;
	}

	result.cccc = aCert.length;
	result.cccci = aIdx.length;

	for (let i = 0; i < aCert.length; i++) {
	    let issuer2 = x.getIssuerHex();
	    let serial2 = x.getSerialNumberHex();
	    if (si.signerid_issuer1 === issuer2 &&
		si.signerid_serial1 === serial2) {
		si.certkey_idx = i;
	    }
	}
    };

    let _verifySignerInfo = function(hCMS, result, si, idx) {
	si.verifyDetail = {};

	let _detail = si.verifyDetail;

	let econtent = result.parse.econtent;

	// verify MessageDigest signed attribute
	let hashalg = si.hashalg;
	let saMessageDigest = si.saMessageDigest;
	
	// verify messageDigest
	_detail.validMessageDigest = false;
	//_detail._econtent = econtent;
	//_detail._hashalg = hashalg;
	//_detail._saMD = saMessageDigest;
	if (hashHex(econtent, hashalg) === saMessageDigest)
	    _detail.validMessageDigest = true;

	// find signing certificate
	_findCert(hCMS, result, si, idx);
	//if (si.signerid_cert === undefined)
	//    throw Error("can't find signer certificate");

	// verify signature value
	_detail.validSignatureValue = false;
	let sigalg = si.sigalg;
	let hSignedAttr = "31" + getTLV(hCMS, si.idxSignedAttrs).substr(2);
	si.signedattrshex = hSignedAttr;
	let pubkey = result.certs[si.certkey_idx].getPublicKey();
	let sig = new Signature({'alg': sigalg});
	sig.init(pubkey);
	sig.updateHex(hSignedAttr);
	let isValid = sig.verify(si.sigval);
	_detail.validSignatureValue_isValid = isValid;
	if (isValid === true)
	    _detail.validSignatureValue = true;

	// verify SignerInfo totally
	si.isValid =false;
	if (_detail.validMessageDigest &&
	    _detail.validSignatureValue) {
	    si.isValid = true;
	}
    };

    let _findSignerCert = function() {
    };

    let result = { isValid: false, parse: {} };
    _parseSignedData(hCMS, result.parse);

    _verify(hCMS, result);
    
    return result;
};


