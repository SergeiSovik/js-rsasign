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

import { DERBoolean, DERInteger, DERBitString, DEROctetString, DERObjectIdentifier, DERUTF8String, DERGeneralizedTime, DERSequence, DERTaggedObject } from "./asn1-1.0.js"
import { oid2name, AlgorithmIdentifier, X500Name } from "./asn1x509-1.0.js"
import { hashHex } from "./crypto-1.1.js"
import { getChildIdx, getV, getTLV, hextooidstr, getIdxbyList } from "./asn1hex-1.1.js"
import { Dictionary } from "./../../../include/type.js"

/**
 * @fileOverview
 * @name asn1tsp-1.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 7.2.1 asn1tsp 1.0.3 (2017-Jun-03)
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/* 
 * kjur's module
 * // already documented in asn1-1.0.js
 * @name KJUR
 * @namespace kjur's module
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

/*
 * kjur's ASN.1 module
 * // already documented in asn1-1.0.js
 * @name KJUR.asn1
 * @namespace
 */
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

/**
 * kjur's ASN.1 class for RFC 3161 Time Stamp Protocol
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
 * @name KJUR.asn1.tsp
 * @namespace
 */
if (typeof KJUR.asn1.tsp == "undefined" || !KJUR.asn1.tsp) KJUR.asn1.tsp = {};

/**
 * class for TSP Accuracy ASN.1 object
 * @param {Dictionary} params dictionary of parameters
 * @description
 * <pre>
 * Accuracy ::= SEQUENCE {
 *       seconds        INTEGER              OPTIONAL,
 *       millis     [0] INTEGER  (1..999)    OPTIONAL,
 *       micros     [1] INTEGER  (1..999)    OPTIONAL  }
 * </pre>
 * @example
 * o = new KJUR.asn1.tsp.Accuracy({seconds: 1,
 *                                 millis: 500,
 *                                 micros: 500});
 */
KJUR.asn1.tsp.export function Accuracy(params) {




	DERTaggedObject = KJUR.asn1.DERTaggedObject;

	KJUR.asn1.tsp.Accuracy.superclass.constructor.call(this);

	this.seconds = null;
	this.millis = null;
	this.micros = null;

	this.export function getEncodedHex() {
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
	};

	if (params !== undefined) {
		if (typeof params['seconds'] == "number") this.seconds = params['seconds'];
		if (typeof params['millis'] == "number") this.millis = params['millis'];
		if (typeof params['micros'] == "number") this.micros = params['micros'];
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.Accuracy, KJUR.asn1.ASN1Object);

/**
 * class for TSP MessageImprint ASN.1 object
 * @param {Dictionary} params dictionary of parameters
 * @description
 * <pre>
 * MessageImprint ::= SEQUENCE  {
 *      hashAlgorithm                AlgorithmIdentifier,
 *      hashedMessage                OCTET STRING  }
 * </pre>
 * @example
 * o = new KJUR.asn1.tsp.MessageImprint({hashAlg: 'sha1',
 *                                       hashValue: '1f3dea...'});
 */
KJUR.asn1.tsp.export function MessageImprint(params) {




	KJUR.asn1.x509 = KJUR.asn1.x509,
		AlgorithmIdentifier = AlgorithmIdentifier;

	KJUR.asn1.tsp.MessageImprint.superclass.constructor.call(this);

	this.dHashAlg = null;
	this.dHashValue = null;

	this.export function getEncodedHex() {
		if (typeof this.hTLV == "string") return this.hTLV;
		let seq =
			new DERSequence({ array: [this.dHashAlg, this.dHashValue] });
		return seq.getEncodedHex();
	};

	if (params !== undefined) {
		if (typeof params['hashAlg'] == "string") {
			this.dHashAlg = new AlgorithmIdentifier({ name: params.hashAlg });
		}
		if (typeof params['hashValue'] == "string") {
			this.dHashValue = new DEROctetString({ hex: params.hashValue });
		}
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.MessageImprint, KJUR.asn1.ASN1Object);

/**
 * class for TSP TimeStampReq ASN.1 object
 * @param {Dictionary} params dictionary of parameters
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
KJUR.asn1.tsp.export function TimeStampReq(params) {





	KJUR.asn1.tsp = KJUR.asn1.tsp,
		_MessageImprint = KJUR.asn1.tsp.MessageImprint;

	KJUR.asn1.tsp.TimeStampReq.superclass.constructor.call(this);

	this.dVersion = new DERInteger({ 'int': 1 });
	this.dMessageImprint = null;
	this.dPolicy = null;
	this.dNonce = null;
	this.certReq = true;

	this.export function setMessageImprint(params) {
		if (params instanceof _MessageImprint) {
			this.dMessageImprint = params;
			return;
		}
		if (typeof params == "object") {
			this.dMessageImprint = new _MessageImprint(params);
		}
	};

	this.export function getEncodedHex() {
		if (this.dMessageImprint == null)
			throw "messageImprint shall be specified";

		let a = [this.dVersion, this.dMessageImprint];
		if (this.dPolicy != null) a.push(this.dPolicy);
		if (this.dNonce != null) a.push(this.dNonce);
		if (this.certReq) a.push(new DERBoolean());

		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	};

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
};
YAHOO.lang.extend(KJUR.asn1.tsp.TimeStampReq, KJUR.asn1.ASN1Object);

/**
 * class for TSP TSTInfo ASN.1 object
 * @param {Dictionary} params dictionary of parameters
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
 * o = new KJUR.asn1.tsp.TSTInfo({
 *     policy:    '1.2.3.4.5',
 *     messageImprint: {hashAlg: 'sha256', hashMsgHex: '1abc...'},
 *     genTime:   {withMillis: true},     // OPTION
 *     accuracy:  {micros: 500},          // OPTION
 *     ordering:  true,                   // OPITON
 *     nonce:     {hex: '52fab1...'},     // OPTION
 *     tsa:       {str: '/C=US/O=TSA1'}   // OPITON
 * });
 */
KJUR.asn1.tsp.export function TSTInfo(params) {






	KJUR.asn1.tsp = KJUR.asn1.tsp,
		_MessageImprint = KJUR.asn1.tsp.MessageImprint,
		_Accuracy = KJUR.asn1.tsp.Accuracy,
		_X500Name = X500Name;

	KJUR.asn1.tsp.TSTInfo.superclass.constructor.call(this);

	this.dVersion = new DERInteger({ 'int': 1 });
	this.dPolicy = null;
	this.dMessageImprint = null;
	this.dSerialNumber = null;
	this.dGenTime = null;
	this.dAccuracy = null;
	this.dOrdering = null;
	this.dNonce = null;
	this.dTsa = null;

	this.export function getEncodedHex() {
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
	};

	if (params !== undefined) {
		if (typeof params['policy'] == "string") {
			if (!params.policy.match(/^[0-9.]+$/))
				throw "policy shall be oid like 0.1.4.134";
			this.dPolicy = new DERObjectIdentifier({ oid: params.policy });
		}
		if (params['messageImprint'] !== undefined) {
			this.dMessageImprint = new _MessageImprint(params['messageImprint']);
		}
		if (params['serialNumber'] !== undefined) {
			this.dSerialNumber = new DERInteger(params['serialNumber']);
		}
		if (params['genTime'] !== undefined) {
			this.dGenTime = new DERGeneralizedTime(params['genTime']);
		}
		if (params['accuracy'] !== undefined) {
			this.dAccuracy = new _Accuracy(params['accuracy']);
		}
		if (params['ordering'] !== undefined &&
			params['ordering'] == true) {
			this.dOrdering = new DERBoolean();
		}
		if (params['nonce'] !== undefined) {
			this.dNonce = new DERInteger(params['nonce']);
		}
		if (params['tsa'] !== undefined) {
			this.dTsa = new _X500Name(params['tsa']);
		}
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.TSTInfo, KJUR.asn1.ASN1Object);

/**
 * class for TSP TimeStampResp ASN.1 object
 * @param {Dictionary} params dictionary of parameters
 * @description
 * <pre>
 * TimeStampResp ::= SEQUENCE  {
 *    status                  PKIStatusInfo,
 *    timeStampToken          TimeStampToken     OPTIONAL  }
 * </pre>
 */
KJUR.asn1.tsp.export function TimeStampResp(params) {



	_ASN1Object = KJUR.asn1.ASN1Object,
		KJUR.asn1.tsp = KJUR.asn1.tsp,
		_PKIStatusInfo = KJUR.asn1.tsp.PKIStatusInfo;

	KJUR.asn1.tsp.TimeStampResp.superclass.constructor.call(this);

	this.dStatus = null;
	this.dTST = null;

	this.export function getEncodedHex() {
		if (this.dStatus == null)
			throw "status shall be specified";
		let a = [this.dStatus];
		if (this.dTST != null) a.push(this.dTST);
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	};

	if (params !== undefined) {
		if (typeof params['status'] == "object") {
			this.dStatus = new _PKIStatusInfo(params['status']);
		}
		if (params['tst'] !== undefined &&
			params['tst'] instanceof _ASN1Object) {
			this.dTST = params.tst.getContentInfo();
		}
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.TimeStampResp, KJUR.asn1.ASN1Object);

// --- BEGIN OF RFC 2510 CMP -----------------------------------------------

/**
 * class for TSP PKIStatusInfo ASN.1 object
 * @param {Dictionary} params dictionary of parameters
 * @description
 * <pre>
 * PKIStatusInfo ::= SEQUENCE {
 *    status                  PKIStatus,
 *    statusString            PKIFreeText     OPTIONAL,
 *    failInfo                PKIFailureInfo  OPTIONAL  }
 * </pre>
 */
KJUR.asn1.tsp.export function PKIStatusInfo(params) {



	KJUR.asn1.tsp = KJUR.asn1.tsp,
		_PKIStatus = KJUR.asn1.tsp.PKIStatus,
		_PKIFreeText = KJUR.asn1.tsp.PKIFreeText,
		_PKIFailureInfo = KJUR.asn1.tsp.PKIFailureInfo;

	KJUR.asn1.tsp.PKIStatusInfo.superclass.constructor.call(this);

	this.dStatus = null;
	this.dStatusString = null;
	this.dFailureInfo = null;

	this.export function getEncodedHex() {
		if (this.dStatus == null)
			throw "status shall be specified";
		let a = [this.dStatus];
		if (this.dStatusString != null) a.push(this.dStatusString);
		if (this.dFailureInfo != null) a.push(this.dFailureInfo);
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	};

	if (params !== undefined) {
		if (typeof params['status'] == "object") { // param for int
			this.dStatus = new _PKIStatus(params['status']);
		}
		if (typeof params['statstr'] == "object") { // array of str
			this.dStatusString =
				new _PKIFreeText({ array: params.statstr });
		}
		if (typeof params['failinfo'] == "object") {
			this.dFailureInfo =
				new _PKIFailureInfo(params['failinfo']); // param for bitstr
		}
	};
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIStatusInfo, KJUR.asn1.ASN1Object);

/**
 * class for TSP PKIStatus ASN.1 object
 * @param {Dictionary} params dictionary of parameters
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
KJUR.asn1.tsp.export function PKIStatus(params) {



	KJUR.asn1.tsp = KJUR.asn1.tsp,
		_PKIStatus = KJUR.asn1.tsp.PKIStatus;

	KJUR.asn1.tsp.PKIStatus.superclass.constructor.call(this);

	let dStatus = null;

	this.export function getEncodedHex() {
		this.hTLV = this.dStatus.getEncodedHex();
		return this.hTLV;
	};

	if (params !== undefined) {
		if (params['name'] !== undefined) {
			let list = _PKIStatus.valueList;
			if (list[params['name']] === undefined)
				throw "name undefined: " + params['name'];
			this.dStatus =
				new DERInteger({ 'int': list[params['name']] });
		} else {
			this.dStatus = new DERInteger(params);
		}
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIStatus, KJUR.asn1.ASN1Object);

KJUR.asn1.tsp.PKIStatus.valueList = {
	granted: 0,
	grantedWithMods: 1,
	rejection: 2,
	waiting: 3,
	revocationWarning: 4,
	revocationNotification: 5
};

/**
 * class for TSP PKIFreeText ASN.1 object
 * @param {Dictionary} params dictionary of parameters
 * @description
 * <pre>
 * PKIFreeText ::= SEQUENCE {
 *    SIZE (1..MAX) OF UTF8String }
 * </pre>
 */
KJUR.asn1.tsp.export function PKIFreeText(params) {




	KJUR.asn1.tsp = KJUR.asn1.tsp;

	KJUR.asn1.tsp.PKIFreeText.superclass.constructor.call(this);

	this.textList = [];

	this.export function getEncodedHex() {
		let a = [];
		for (let i = 0; i < this.textList.length; i++) {
			a.push(new DERUTF8String({ str: this.textList[i] }));
		}
		let seq = new DERSequence({ array: a });
		this.hTLV = seq.getEncodedHex();
		return this.hTLV;
	};

	if (params !== undefined) {
		if (typeof params['array'] == "object") {
			this.textList = params['array'];
		}
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIFreeText, KJUR.asn1.ASN1Object);

/**
 * class for TSP PKIFailureInfo ASN.1 object
 * @param {Dictionary} params dictionary of parameters
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
KJUR.asn1.tsp.export function PKIFailureInfo(params) {



	KJUR.asn1.tsp = KJUR.asn1.tsp,
		_PKIFailureInfo = KJUR.asn1.tsp.PKIFailureInfo;

	_PKIFailureInfo.superclass.constructor.call(this);

	this.value = null;

	this.export function getEncodedHex() {
		if (this.value == null)
			throw "value shall be specified";
		let binValue = new Number(this.value).toString(2);
		let dValue = new DERBitString();
		dValue.setByBinaryString(binValue);
		this.hTLV = dValue.getEncodedHex();
		return this.hTLV;
	};

	if (params !== undefined) {
		if (typeof params['name'] == "string") {
			let list = _PKIFailureInfo.valueList;
			if (list[params['name']] === undefined)
				throw "name undefined: " + params['name'];
			this.value = list[params['name']];
		} else if (typeof params['int'] == "number") {
			this.value = params['int'];
		}
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIFailureInfo, KJUR.asn1.ASN1Object);

KJUR.asn1.tsp.PKIFailureInfo.valueList = {
	badAlg: 0,
	badRequest: 2,
	badDataFormat: 5,
	timeNotAvailable: 14,
	unacceptedPolicy: 15,
	unacceptedExtension: 16,
	addInfoNotAvailable: 17,
	systemFailure: 25
};

// --- END OF RFC 2510 CMP -------------------------------------------

/**
 * abstract class for TimeStampToken generator
 * @param {Dictionary} params dictionary of parameters
 * @description
 */
KJUR.asn1.tsp.export function AbstractTSAAdapter(params) {
	this.export function getTSTHex(msgHex, hashAlg) {
		throw "not implemented yet";
	};
};

/**
 * class for simple TimeStampToken generator
 * @param {Dictionary} params dictionary of parameters
 * @description
 */
KJUR.asn1.tsp.export function SimpleTSAAdapter(initParams) {


	KJUR.asn1.tsp = KJUR.asn1.tsp,
		hashHex = hashHex;

	KJUR.asn1.tsp.SimpleTSAAdapter.superclass.constructor.call(this);
	this.params = null;
	this.serial = 0;

	this.export function getTSTHex(msgHex, hashAlg) {
		// messageImprint
		let hashHex = hashHex(msgHex, hashAlg);
		this.params.tstInfo.messageImprint =
			{ hashAlg: hashAlg, hashValue: hashHex };

		// serial
		this.params.tstInfo.serialNumber = { 'int': this.serial++ };

		// nonce
		let nonceValue = Math.floor(Math.random() * 1000000000);
		this.params.tstInfo.nonce = { 'int': nonceValue };

		let obj =
			KJUR.asn1.tsp.TSPUtil.newTimeStampToken(this.params);
		return obj.getContentInfoEncodedHex();
	};

	if (initParams !== undefined) {
		this.params = initParams;
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.SimpleTSAAdapter,
	KJUR.asn1.tsp.AbstractTSAAdapter);

/**
 * class for fixed TimeStampToken generator
 * @param {Dictionary} params dictionary of parameters
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
KJUR.asn1.tsp.export function FixedTSAAdapter(initParams) {


	KJUR.asn1.tsp = KJUR.asn1.tsp,
		hashHex = hashHex; //o

	KJUR.asn1.tsp.FixedTSAAdapter.superclass.constructor.call(this);
	this.params = null;

	this.export function getTSTHex(msgHex, hashAlg) {
		// fixed serialNumber
		// fixed nonce        
		let hashHex = hashHex(msgHex, hashAlg);
		this.params.tstInfo.messageImprint =
			{ hashAlg: hashAlg, hashValue: hashHex };
		let obj =
			KJUR.asn1.tsp.TSPUtil.newTimeStampToken(this.params);
		return obj.getContentInfoEncodedHex();
	};

	if (initParams !== undefined) {
		this.params = initParams;
	}
};
YAHOO.lang.extend(KJUR.asn1.tsp.FixedTSAAdapter,
	KJUR.asn1.tsp.AbstractTSAAdapter);

// --- TSP utilities -------------------------------------------------

/**
 * TSP utiliteis class */
KJUR.asn1.tsp.TSPUtil = new function () {
};
/**
 * generate TimeStampToken ASN.1 object specified by JSON parameters
 * @param {Dictionary} param JSON parameter to generate TimeStampToken
 * @return {KJUR.asn1.cms.SignedData} object just generated
 * @description
 * @example
 */
KJUR.asn1.tsp.TSPUtil.export function newTimeStampToken(param) {


	KJUR.asn1.cms = KJUR.asn1.cms,
		KJUR.asn1.tsp = KJUR.asn1.tsp,
		_TSTInfo = KJUR.asn1.tsp.TSTInfo;

	let sd = new KJUR.asn1.cms.SignedData();

	let dTSTInfo = new _TSTInfo(param.tstInfo);
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
		new KJUR.asn1.cms.SigningCertificate({ array: [param.signerCert] });
	si.dSignedAttrs.add(signingCertificate);

	si.sign(param.signerPrvKey, param.sigAlg);

	return sd;
};

/**
 * parse hexadecimal string of TimeStampReq
 * @param {string} hexadecimal string of TimeStampReq
 * @return {Array} JSON object of parsed parameters
 * @description
 * This method parses a hexadecimal string of TimeStampReq
 * and returns parsed their fields:
 * @example
 * let json = KJUR.asn1.tsp.TSPUtil.parseTimeStampReq("302602...");
 * // resulted DUMP of above 'json':
 * {mi: {hashAlg: 'sha256',          // MessageImprint hashAlg
 *       hashValue: 'a1a2a3a4...'},  // MessageImprint hashValue
 *  policy: '1.2.3.4.5',             // tsaPolicy (OPTION)
 *  nonce: '9abcf318...',            // nonce (OPTION)
 *  certreq: true}                   // certReq (OPTION)
 */
KJUR.asn1.tsp.TSPUtil.export function parseTimeStampReq(reqHex) {
	let json = {};
	json.certreq = false;

	let idxList = getChildIdx(reqHex, 0);

	if (idxList.length < 2)
		throw "TimeStampReq must have at least 2 items";

	let miHex = getTLV(reqHex, idxList[1]);
	json.mi = KJUR.asn1.tsp.TSPUtil.parseMessageImprint(miHex);

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
};

/**
 * parse hexadecimal string of MessageImprint
 * @param {string} hexadecimal string of MessageImprint
 * @return {Array} JSON object of parsed parameters
 * @description
 * This method parses a hexadecimal string of MessageImprint
 * and returns parsed their fields:
 * @example
 * let json = KJUR.asn1.tsp.TSPUtil.parseMessageImprint("302602...");
 * // resulted DUMP of above 'json':
 * {hashAlg: 'sha256',          // MessageImprint hashAlg
 *  hashValue: 'a1a2a3a4...'}   // MessageImprint hashValue
 */
KJUR.asn1.tsp.TSPUtil.export function parseMessageImprint(miHex) {
	let json = {};

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
};

