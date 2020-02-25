/*
 * asn1tsp.js - ASN.1 DER encoder classes for RFC 3161 Time Stamp Protocol
 *
 * Original work Copyright (c) 2014-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { ASN1Object, DERBoolean, DERInteger, DERBitString, DEROctetString, DERObjectIdentifier, DERUTF8String, DERGeneralizedTime, DERSequence, DERTaggedObject } from "./asn1-1.0.js"
import { oid2name } from "./asn1oid.js"
import { AlgorithmIdentifier, X500Name } from "./asn1x509-1.0.js"
import { hashHex } from "./crypto-1.1.js"
import { getChildIdx, getV, getTLV, hextooidstr, getIdxbyList } from "./asn1hex-1.1.js"
import { Dictionary } from "./../../../include/type.js"
import { SignedData, SigningCertificate } from "./asn1cms-1.0.js"

/**
 * ASN.1 module for RFC 3161 Time Stamp Protocol
 * <p>
 * This module provides 
 * <a href="https://tools.ietf.org/html/rfc3161">RFC 3161
 * Time-Stamp Protocol(TSP)</a> data generator.
 *
 * <h4>FEATURES</h4>
 * <ul>
 * <li>easily generate CMS SignedData</li>
 * <li>APIs are very similar to BouncyCastle library ASN.1 classes. So easy to learn.</li>
 * </ul>
 * 
 * <h4>PROVIDED CLASSES</h4>
 * <ul>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 */

/**
 * class for TSP Accuracy ASN.1 object
 * @description
 * <pre>
 * Accuracy ::= SEQUENCE {
 *       seconds        INTEGER              OPTIONAL,
 *       millis     [0] INTEGER  (1..999)    OPTIONAL,
 *       micros     [1] INTEGER  (1..999)    OPTIONAL  }
 * </pre>
 * @example
 * o = new Accuracy({seconds: 1,
 *                                 millis: 500,
 *                                 micros: 500});
 */
export class Accuracy extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {number | null} */ this.seconds = null;
		/** @type {number | null} */ this.millis = null;
		/** @type {number | null} */ this.micros = null;

		if (params !== undefined) {
			if (typeof params['seconds'] == "number") this.seconds = params['seconds'];
			if (typeof params['millis'] == "number") this.millis = params['millis'];
			if (typeof params['micros'] == "number") this.micros = params['micros'];
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let dSeconds = null;
		let dTagMillis = null;
		let dTagMicros = null;

		let a = [];
		if (this.seconds != null) {
			dSeconds = new DERInteger({ 'int': this.seconds });
			a.push(dSeconds);
		}
		if (this.millis != null) {
			let dMillis = new DERInteger({ 'int': this.millis });
			dTagMillis = new DERTaggedObject({
				obj: dMillis,
				tag: '80',
				explicit: false
			});
			a.push(dTagMillis);
		}
		if (this.micros != null) {
			let dMicros = new DERInteger({ 'int': this.micros });
			dTagMicros = new DERTaggedObject({
				obj: dMicros,
				tag: '81',
				explicit: false
			});
			a.push(dTagMicros);
		}
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for TSP MessageImprint ASN.1 object
 * @description
 * <pre>
 * MessageImprint ::= SEQUENCE  {
 *      hashAlgorithm                AlgorithmIdentifier,
 *      hashedMessage                OCTET STRING  }
 * </pre>
 * @example
 * o = new MessageImprint({hashAlg: 'sha1',
 *                                       hashValue: '1f3dea...'});
 */
export class MessageImprint extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {AlgorithmIdentifier | null} */ this.dHashAlg = null;
		/** @type {DEROctetString | null} */ this.dHashValue = null;

		if (params !== undefined) {
			if (typeof params['hashAlg'] == "string") {
				this.dHashAlg = new AlgorithmIdentifier({ name: params.hashAlg });
			}
			if (typeof params['hashValue'] == "string") {
				this.dHashValue = new DEROctetString({ hex: params.hashValue });
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (typeof this.hTLV == "string") return this.hTLV;
		let seq =
			new DERSequence({ array: [this.dHashAlg, this.dHashValue] });
		return seq.getEncodedHex();
	}
}

/**
 * class for TSP TimeStampReq ASN.1 object
 * @description
 * <pre>
 * TimeStampReq ::= SEQUENCE  {
 *    version          INTEGER  { v1(1) },
 *    messageImprint   MessageImprint,
 *    reqPolicy        TSAPolicyId               OPTIONAL,
 *    nonce            INTEGER                   OPTIONAL,
 *    certReq          BOOLEAN                   DEFAULT FALSE,
 *    extensions       [0] IMPLICIT Extensions   OPTIONAL  }
 * </pre>
 */
export class TimeStampReq extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		this.dVersion = new DERInteger({ 'int': 1 });
		this.dMessageImprint = null;
		this.dPolicy = null;
		this.dNonce = null;
		this.certReq = true;

		if (params !== undefined) {
			if (typeof params['mi'] == "object") {
				this.setMessageImprint(params['mi']);
			}
			if (typeof params['policy'] == "object") {
				this.dPolicy = new DERObjectIdentifier(params['policy']);
			}
			if (typeof params['nonce'] == "object") {
				this.dNonce = new DERInteger(params['nonce']);
			}
			if (typeof params['certreq'] == "boolean") {
				this.certReq = params['certreq'];
			}
		}
	}

	/**
	 * @param {MessageImprint | Dictionary} params 
	 */
	setMessageImprint(params) {
		if (params instanceof MessageImprint) {
			this.dMessageImprint = params;
			return;
		}
		if (typeof params == "object") {
			this.dMessageImprint = new MessageImprint(params);
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.dMessageImprint == null)
			throw "messageImprint shall be specified";

		let a = [this.dVersion, this.dMessageImprint];
		if (this.dPolicy != null) a.push(this.dPolicy);
		if (this.dNonce != null) a.push(this.dNonce);
		if (this.certReq) a.push(new DERBoolean());

		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for TSP TSTInfo ASN.1 object
 * @description
 * <pre>
 * TSTInfo ::= SEQUENCE  {
 *    version         INTEGER  { v1(1) },
 *    policy          TSAPolicyId,
 *    messageImprint  MessageImprint,
 *    serialNumber    INTEGER, -- up to 160bit
 *    genTime         GeneralizedTime,
 *    accuracy        Accuracy                 OPTIONAL,
 *    ordering        BOOLEAN                  DEFAULT FALSE,
 *    nonce           INTEGER                  OPTIONAL,
 *    tsa             [0] GeneralName          OPTIONAL,
 *    extensions      [1] IMPLICIT Extensions  OPTIONAL   }
 * </pre>
 * @example
 * o = new TSTInfo({
 *     policy:    '1.2.3.4.5',
 *     messageImprint: {hashAlg: 'sha256', hashMsgHex: '1abc...'},
 *     genTime:   {withMillis: true},     // OPTION
 *     accuracy:  {micros: 500},          // OPTION
 *     ordering:  true,                   // OPITON
 *     nonce:     {hex: '52fab1...'},     // OPTION
 *     tsa:       {str: '/C=US/O=TSA1'}   // OPITON
 * });
 */
export class TSTInfo extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		this.dVersion = new DERInteger({ 'int': 1 });
		/** @type {DERObjectIdentifier | null} */ this.dPolicy = null;
		/** @type {MessageImprint | null} */ this.dMessageImprint = null;
		/** @type {DERInteger | null} */ this.dSerialNumber = null;
		/** @type {DERGeneralizedTime | null} */ this.dGenTime = null;
		/** @type {Accuracy | null} */ this.dAccuracy = null;
		/** @type {DERBoolean | null} */ this.dOrdering = null;
		/** @type {DERInteger | null} */ this.dNonce = null;
		/** @type {X500Name | null} */ this.dTsa = null;

		if (params !== undefined) {
			if (typeof params['policy'] == "string") {
				if (!params.policy.match(/^[0-9.]+$/))
					throw "policy shall be oid like 0.1.4.134";
				this.dPolicy = new DERObjectIdentifier({ oid: params.policy });
			}
			if (params['messageImprint'] !== undefined) {
				this.dMessageImprint = new MessageImprint(params['messageImprint']);
			}
			if (params['serialNumber'] !== undefined) {
				this.dSerialNumber = new DERInteger(params['serialNumber']);
			}
			if (params['genTime'] !== undefined) {
				this.dGenTime = new DERGeneralizedTime(params['genTime']);
			}
			if (params['accuracy'] !== undefined) {
				this.dAccuracy = new Accuracy(params['accuracy']);
			}
			if (params['ordering'] !== undefined &&
				params['ordering'] == true) {
				this.dOrdering = new DERBoolean();
			}
			if (params['nonce'] !== undefined) {
				this.dNonce = new DERInteger(params['nonce']);
			}
			if (params['tsa'] !== undefined) {
				this.dTsa = new X500Name(params['tsa']);
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let a = [this.dVersion];

		if (this.dPolicy == null) throw "policy shall be specified.";
		a.push(this.dPolicy);

		if (this.dMessageImprint == null)
			throw "messageImprint shall be specified.";
		a.push(this.dMessageImprint);

		if (this.dSerialNumber == null)
			throw "serialNumber shall be specified.";
		a.push(this.dSerialNumber);

		if (this.dGenTime == null)
			throw "genTime shall be specified.";
		a.push(this.dGenTime);

		if (this.dAccuracy != null) a.push(this.dAccuracy);
		if (this.dOrdering != null) a.push(this.dOrdering);
		if (this.dNonce != null) a.push(this.dNonce);
		if (this.dTsa != null) a.push(this.dTsa);

		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for TSP TimeStampResp ASN.1 object
 * @description
 * <pre>
 * TimeStampResp ::= SEQUENCE  {
 *    status                  PKIStatusInfo,
 *    timeStampToken          TimeStampToken     OPTIONAL  }
 * </pre>
 */
export class TimeStampResp extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		/** @type {PKIStatusInfo | null} */ this.dStatus = null;
		/** @type {ContentInfo | null} */ this.dTST = null;

		if (params !== undefined) {
			if (typeof params['status'] == "object") {
				this.dStatus = new PKIStatusInfo(params['status']);
			}
			if (params['tst'] !== undefined &&
				params['tst'] instanceof SignedData) {
				this.dTST = params.tst.getContentInfo();
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.dStatus == null)
			throw "status shall be specified";
		let a = [this.dStatus];
		if (this.dTST != null) a.push(this.dTST);
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

// --- BEGIN OF RFC 2510 CMP -----------------------------------------------

/**
 * class for TSP PKIStatusInfo ASN.1 object
 * @description
 * <pre>
 * PKIStatusInfo ::= SEQUENCE {
 *    status                  PKIStatus,
 *    statusString            PKIFreeText     OPTIONAL,
 *    failInfo                PKIFailureInfo  OPTIONAL  }
 * </pre>
 */
export class PKIStatusInfo extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		/** @type {PKIStatus | null} */ this.dStatus = null;
		/** @type {PKIFreeText | null} */ this.dStatusString = null;
		/** @type {PKIFailureInfo | null} */ this.dFailureInfo = null;

		if (params !== undefined) {
			if (typeof params['status'] == "object") { // param for int
				this.dStatus = new PKIStatus(params['status']);
			}
			if (typeof params['statstr'] == "object") { // array of str
				this.dStatusString =
					new PKIFreeText({ array: params.statstr });
			}
			if (typeof params['failinfo'] == "object") {
				this.dFailureInfo =
					new PKIFailureInfo(params['failinfo']); // param for bitstr
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.dStatus == null)
			throw "status shall be specified";
		let a = [this.dStatus];
		if (this.dStatusString != null) a.push(this.dStatusString);
		if (this.dFailureInfo != null) a.push(this.dFailureInfo);
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/** @dict */
const PKIStatusValueList = {
	'granted': 0,
	'grantedWithMods': 1,
	'rejection': 2,
	'waiting': 3,
	'revocationWarning': 4,
	'revocationNotification': 5
};

/**
 * class for TSP PKIStatus ASN.1 object
 * @description
 * <pre>
 * PKIStatus ::= INTEGER {
 *    granted                (0),
 *    grantedWithMods        (1),
 *    rejection              (2),
 *    waiting                (3),
 *    revocationWarning      (4),
 *    revocationNotification (5) }
 * </pre>
 */
export class PKIStatus extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {DERInteger | null} */ let dStatus = null;

		if (params !== undefined) {
			if (params['name'] !== undefined) {
				let list = PKIStatusValueList;
				if (list[params['name']] === undefined)
					throw "name undefined: " + params['name'];
				this.dStatus =
					new DERInteger({ 'int': list[params['name']] });
			} else {
				this.dStatus = new DERInteger(params);
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		this.hTLV = this.dStatus.getEncodedHex();
		return this.hTLV;
	}
}

/**
 * class for TSP PKIFreeText ASN.1 object
 * @description
 * <pre>
 * PKIFreeText ::= SEQUENCE {
 *    SIZE (1..MAX) OF UTF8String }
 * </pre>
 */
export class PKIFreeText extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super(params);

		/** @type {Array<string>} */ this.textList = [];

		if (params !== undefined) {
			if (typeof params['array'] == "object") {
				this.textList = params['array'];
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		let a = [];
		for (let i = 0; i < this.textList.length; i++) {
			a.push(new DERUTF8String({ str: this.textList[i] }));
		}
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	}
}

/** @dict */
const PKIFailureInfoValueList = {
	'badAlg': 0,
	'badRequest': 2,
	'badDataFormat': 5,
	'timeNotAvailable': 14,
	'unacceptedPolicy': 15,
	'unacceptedExtension': 16,
	'addInfoNotAvailable': 17,
	'systemFailure': 25
};

/**
 * class for TSP PKIFailureInfo ASN.1 object
 * @description
 * <pre>
 * PKIFailureInfo ::= BIT STRING {
 *    badAlg                 (0),
 *    badRequest             (2),
 *    badDataFormat          (5),
 *    timeNotAvailable       (14),
 *    unacceptedPolicy       (15),
 *    unacceptedExtension    (16),
 *    addInfoNotAvailable    (17),
 *    systemFailure          (25) }
 * </pre>
 */
export class PKIFailureInfo extends ASN1Object {
	/**
	 * @param {Dictionary} params dictionary of parameters
	 */
	constructor(params) {
		super();

		/** @type {number | null} */ this.value = null;

		if (params !== undefined) {
			if (typeof params['name'] == "string") {
				let list = PKIFailureInfoValueList;
				if (list[params['name']] === undefined)
					throw "name undefined: " + params['name'];
				this.value = list[params['name']];
			} else if (typeof params['int'] == "number") {
				this.value = params['int'];
			}
		}
	}

	/**
	 * @override
	 * @returns {string}
	 */
	getEncodedHex() {
		if (this.value == null)
			throw "value shall be specified";
		let binValue = new Number(this.value).toString(2);
		let dValue = new DERBitString();
		dValue.setByBinaryString(binValue);
		this.hTLV = dValue.getEncodedHex();
		return this.hTLV;
	}
}

// --- END OF RFC 2510 CMP -------------------------------------------

/**
 * abstract class for TimeStampToken generator
 * @abstract
 * @description
 */
export class AbstractTSAAdapter {
	/**
	 * @abstract
	 * @param {string} msgHex 
	 * @param {string} hashAlg 
	 * @returns {string}
	 */
	getTSTHex(msgHex, hashAlg) {}
}

/**
 * class for simple TimeStampToken generator
 * @description
 */
export class SimpleTSAAdapter extends AbstractTSAAdapter {
	/**
	 * @param {Dictionary} initParams dictionary of parameters
	 */
	constructor(initParams) {
		super();

		/** @type {Dictionary | null} */ this.params = null;
		this.serial = 0;

		if (initParams !== undefined) {
			this.params = initParams;
		}
	}
	
	/**
	 * @param {string} msgHex 
	 * @param {string} hashAlg 
	 * @returns {string}
	 */
	getTSTHex(msgHex, hashAlg) {
		// messageImprint
		let sHashHex = hashHex(msgHex, hashAlg);
		this.params.tstInfo.messageImprint =
			{ hashAlg: hashAlg, hashValue: sHashHex };

		// serial
		this.params.tstInfo.serialNumber = { 'int': this.serial++ };

		// nonce
		let nonceValue = Math.floor(Math.random() * 1000000000);
		this.params.tstInfo.nonce = { 'int': nonceValue };

		let obj = newTimeStampToken(this.params);
		return obj.getContentInfoEncodedHex();
	}
}

/**
 * class for fixed TimeStampToken generator
 * @description
 * This class generates fixed TimeStampToken except messageImprint
 * for testing purpose.
 * General TSA generates TimeStampToken which varies following
 * fields:
 * <ul>
 * <li>genTime</li>
 * <li>serialNumber</li>
 * <li>nonce</li>
 * </ul>
 * Those values are provided by initial parameters.
 */
export class FixedTSAAdapter extends AbstractTSAAdapter {
	/**
 	 * @param {Dictionary} initParams dictionary of parameters
	 */
	constructor(initParams) {
		super();
		
		/** @type {Dictionary | null} */ this.params = null;

		if (initParams !== undefined) {
			this.params = initParams;
		}
	}

	/**
	 * @param {string} msgHex 
	 * @param {string} hashAlg 
	 * @returns {string}
	 */
	getTSTHex(msgHex, hashAlg) {
		// fixed serialNumber
		// fixed nonce        
		let sHashHex = hashHex(msgHex, hashAlg);
		this.params.tstInfo.messageImprint = { hashAlg: hashAlg, hashValue: sHashHex };
		let obj = newTimeStampToken(this.params);
		return obj.getContentInfoEncodedHex();
	}
}

// --- TSP utilities -------------------------------------------------

/**
 * generate TimeStampToken ASN.1 object specified by JSON parameters
 * @param {Dictionary} param JSON parameter to generate TimeStampToken
 * @return {SignedData} object just generated
 * @description
 * @example
 */
export function newTimeStampToken(param) {
	let sd = new SignedData();

	let dTSTInfo = new TSTInfo(param.tstInfo);
	let tstInfoHex = dTSTInfo.getEncodedHex();
	sd.dEncapContentInfo.setContentValue({ 'hex': tstInfoHex });
	sd.dEncapContentInfo.setContentType('tstinfo');

	if (typeof param['certs'] == "object") {
		for (let i = 0; i < param['certs'].length; i++) {
			sd.addCertificatesByPEM(param['certs'][i]);
		}
	}

	let si = sd.signerInfoList[0];
	si.setSignerIdentifier(param.signerCert);
	si.setForContentAndHash({
		sdObj: sd,
		eciObj: sd.dEncapContentInfo,
		hashAlg: param.hashAlg
	});
	let signingCertificate =
		new SigningCertificate({ array: [param.signerCert] });
	si.dSignedAttrs.add(signingCertificate);

	si.sign(param.signerPrvKey, param.sigAlg);

	return sd;
}

/**
 * parse hexadecimal string of TimeStampReq
 * @param {string} hexadecimal string of TimeStampReq
 * @return {Dictionary} JSON object of parsed parameters
 * @description
 * This method parses a hexadecimal string of TimeStampReq
 * and returns parsed their fields:
 * @example
 * let json = TSPUtil.parseTimeStampReq("302602...");
 * // resulted DUMP of above 'json':
 * {mi: {hashAlg: 'sha256',          // MessageImprint hashAlg
 *       hashValue: 'a1a2a3a4...'},  // MessageImprint hashValue
 *  policy: '1.2.3.4.5',             // tsaPolicy (OPTION)
 *  nonce: '9abcf318...',            // nonce (OPTION)
 *  certreq: true}                   // certReq (OPTION)
 */
export function parseTimeStampReq(reqHex) {
	let json = /** @type {Dictionary} */ ( {} );
	json.certreq = false;

	let idxList = getChildIdx(reqHex, 0);

	if (idxList.length < 2)
		throw "TimeStampReq must have at least 2 items";

	let miHex = getTLV(reqHex, idxList[1]);
	json.mi = parseMessageImprint(miHex);

	for (let i = 2; i < idxList.length; i++) {
		let idx = idxList[i];
		let tag = reqHex.substr(idx, 2);
		if (tag == "06") { // case OID
			let policyHex = getV(reqHex, idx);
			json.policy = hextooidstr(policyHex);
		}
		if (tag == "02") { // case INTEGER
			json.nonce = getV(reqHex, idx);
		}
		if (tag == "01") { // case BOOLEAN
			json.certreq = true;
		}
	}

	return json;
}

/**
 * parse hexadecimal string of MessageImprint
 * @param {string} hexadecimal string of MessageImprint
 * @return {Dictionary} JSON object of parsed parameters
 * @description
 * This method parses a hexadecimal string of MessageImprint
 * and returns parsed their fields:
 * @example
 * let json = TSPUtil.parseMessageImprint("302602...");
 * // resulted DUMP of above 'json':
 * {hashAlg: 'sha256',          // MessageImprint hashAlg
 *  hashValue: 'a1a2a3a4...'}   // MessageImprint hashValue
 */
export function parseMessageImprint(miHex) {
	let json = /** @type {Dictionary} */ ( {} );

	if (miHex.substr(0, 2) != "30")
		throw "head of messageImprint hex shall be '30'";

	let idxList = getChildIdx(miHex, 0);
	let hashAlgOidIdx = getIdxbyList(miHex, 0, [0, 0]);
	let hashAlgHex = getV(miHex, hashAlgOidIdx);
	let hashAlgOid = hextooidstr(hashAlgHex);
	let hashAlgName = oid2name(hashAlgOid);
	if (hashAlgName == '')
		throw "hashAlg name undefined: " + hashAlgOid;
	let hashAlg = hashAlgName;
	let hashValueIdx = getIdxbyList(miHex, 0, [1]);

	json.hashAlg = hashAlg;
	json.hashValue = getV(miHex, hashValueIdx);

	return json;
}
