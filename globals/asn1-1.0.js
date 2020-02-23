/*
 * asn1.js - ASN.1 DER encoder classes
 *
 * Original work Copyright (c) 2013-2018 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { BigInteger } from "./../../js-bn/modules/jsbn.js"
import { hextopem, utf8tohex, stohex } from "./base64x-1.1.js"
import { name2oid } from "./asn1oid.js"

/** 
 * <p>
 * This module provides following name spaces:
 * <ul>
 * <li>{@link asn1-1.0.js} - ASN.1 primitive hexadecimal encoder</li>
 * <li>{@link asn1x509-1.0.js} - ASN.1 structure for X.509 certificate and CRL</li>
 * <li>{@link crypto-1.1.js} - Java Cryptographic Extension(JCE) style MessageDigest/Signature 
 * class and utilities</li>
 * </ul>
 * </p> 
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 */

/**
 * ASN.1 module
 * <p>
 * This is ITU-T X.690 ASN.1 DER encoder module and
 * class structure and methods is very similar to 
 * org.bouncycastle.asn1 package of 
 * well known BouncyCaslte Cryptography Library.
 * <h4>PROVIDING ASN.1 PRIMITIVES</h4>
 * Here are ASN.1 DER primitive classes.
 * <ul>
 * <li>0x01 {@link DERBoolean}</li>
 * <li>0x02 {@link DERInteger}</li>
 * <li>0x03 {@link DERBitString}</li>
 * <li>0x04 {@link DEROctetString}</li>
 * <li>0x05 {@link DERNull}</li>
 * <li>0x06 {@link DERObjectIdentifier}</li>
 * <li>0x0a {@link DEREnumerated}</li>
 * <li>0x0c {@link DERUTF8String}</li>
 * <li>0x12 {@link DERNumericString}</li>
 * <li>0x13 {@link DERPrintableString}</li>
 * <li>0x14 {@link DERTeletexString}</li>
 * <li>0x16 {@link DERIA5String}</li>
 * <li>0x17 {@link DERUTCTime}</li>
 * <li>0x18 {@link DERGeneralizedTime}</li>
 * <li>0x30 {@link DERSequence}</li>
 * <li>0x31 {@link DERSet}</li>
 * </ul>
 * <h4>OTHER ASN.1 CLASSES</h4>
 * <ul>
 * <li>{@link ASN1Object}</li>
 * <li>{@link DERAbstractString}</li>
 * <li>{@link DERAbstractTime}</li>
 * <li>{@link DERAbstractStructured}</li>
 * <li>{@link DERTaggedObject}</li>
 * </ul>
 * <h4>SUB MODULES</h4>
 * <ul>
 * <li>{@link asn1cades-1.0.js} - CAdES long term signature format</li>
 * <li>{@link asn1cms-1.0.js} - Cryptographic Message Syntax</li>
 * <li>{@link asn1csr-1.0.js} - Certificate Signing Request (CSR/PKCS#10)</li>
 * <li>{@link asn1tsp-1.0.js} - RFC 3161 Timestamping Protocol Format</li>
 * <li>{@link asn1x509-1.0.js} - RFC 5280 X.509 certificate and CRL</li>
 * </ul>
 * </p>
 * NOTE: Please ignore method summary and document of this namespace. 
 * This caused by a bug of jsdoc2.
 */

/**
  * @param {number} i 
  * @returns {string}
  */
export function integerToByteHex(i) {
	let h = i.toString(16);
	if ((h.length % 2) == 1) h = '0' + h;
	return h;
}

/**
 * @param {BigInteger} bigIntegerValue 
 * @returns {string}
 */
export function bigIntToMinTwosComplementsHex(bigIntegerValue) {
	let h = bigIntegerValue.toString(16);
	if (h.substr(0, 1) != '-') {
		if (h.length % 2 == 1) {
			h = '0' + h;
		} else {
			if (!h.match(/^[0-7]/)) {
				h = '00' + h;
			}
		}
	} else {
		let hPos = h.substr(1);
		let xorLen = hPos.length;
		if (xorLen % 2 == 1) {
			xorLen += 1;
		} else {
			if (!h.match(/^[0-7]/)) {
				xorLen += 2;
			}
		}
		let hMask = '';
		for (let i = 0; i < xorLen; i++) {
			hMask += 'f';
		}
		let biMask = new BigInteger(hMask, 16);
		let biNeg = biMask.xor(bigIntegerValue).add(BigInteger.ONE());
		h = biNeg.toString(16).replace(/^-/, '');
	}
	return h;
}

/**
 * get PEM string from hexadecimal data and header string
 * @param {string} dataHex hexadecimal string of PEM body
 * @param {string} pemHeader PEM header string (ex. 'RSA PRIVATE KEY')
 * @return {string} PEM formatted string of input data
 * @description
 * This method converts a hexadecimal string to a PEM string with
 * a specified header. Its line break will be CRLF("\r\n").
 * @example
 * let pem  = getPEMStringFromHex('616161', 'RSA PRIVATE KEY');
 * // value of pem will be:
 * -----BEGIN PRIVATE KEY-----
 * YWFh
 * -----END PRIVATE KEY-----
 */
export function getPEMStringFromHex(dataHex, pemHeader) {
	return hextopem(dataHex, pemHeader);
}

/**
 * generate ASN1Object specifed by JSON parameters
 * @param {Object} param JSON parameter to generate ASN1Object
 * @return {ASN1Object} generated object
 * @description
 * generate any ASN1Object specified by JSON param
 * including ASN.1 primitive or structured.
 * Generally 'param' can be described as follows:
 * <blockquote>
 * {TYPE-OF-ASNOBJ: ASN1OBJ-PARAMETER}
 * </blockquote>
 * 'TYPE-OF-ASN1OBJ' can be one of following symbols:
 * <ul>
 * <li>'bool' - DERBoolean</li>
 * <li>'int' - DERInteger</li>
 * <li>'bitstr' - DERBitString</li>
 * <li>'octstr' - DEROctetString</li>
 * <li>'null' - DERNull</li>
 * <li>'oid' - DERObjectIdentifier</li>
 * <li>'enum' - DEREnumerated</li>
 * <li>'utf8str' - DERUTF8String</li>
 * <li>'numstr' - DERNumericString</li>
 * <li>'prnstr' - DERPrintableString</li>
 * <li>'telstr' - DERTeletexString</li>
 * <li>'ia5str' - DERIA5String</li>
 * <li>'utctime' - DERUTCTime</li>
 * <li>'gentime' - DERGeneralizedTime</li>
 * <li>'seq' - DERSequence</li>
 * <li>'set' - DERSet</li>
 * <li>'tag' - DERTaggedObject</li>
 * </ul>
 * @example
 * newObject({'prnstr': 'aaa'});
 * newObject({'seq': [{'int': 3}, {'prnstr': 'aaa'}]})
 * // ASN.1 Tagged Object
 * newObject({'tag': {'tag': 'a1', 
 *                    'explicit': true,
 *                    'obj': {'seq': [{'int': 3}, {'prnstr': 'aaa'}]}}});
 * // more simple representation of ASN.1 Tagged Object
 * newObject({'tag': ['a1',
 *                    true,
 *                    {'seq': [
 *                      {'int': 3}, 
 *                      {'prnstr': 'aaa'}]}
 *                   ]});
 */
export function newObject(param) {
	if (param === null) return new DERNull();
	let keys = Object.keys(param);
	if (keys.length != 1)
		throw "key of param shall be only one.";
	let key = keys[0];

	if (":bool:int:bitstr:octstr:null:oid:enum:utf8str:numstr:prnstr:telstr:ia5str:utctime:gentime:seq:set:tag:".indexOf(":" + key + ":") == -1)
		throw "undefined key: " + key;

	if (key == "bool") return new DERBoolean(param[key]);
	if (key == "int") return new DERInteger(param[key]);
	if (key == "bitstr") return new DERBitString(param[key]);
	if (key == "octstr") return new DEROctetString(param[key]);
	if (key == "null") return new DERNull(param[key]);
	if (key == "oid") return new DERObjectIdentifier(param[key]);
	if (key == "enum") return new DEREnumerated(param[key]);
	if (key == "utf8str") return new DERUTF8String(param[key]);
	if (key == "numstr") return new DERNumericString(param[key]);
	if (key == "prnstr") return new DERPrintableString(param[key]);
	if (key == "telstr") return new DERTeletexString(param[key]);
	if (key == "ia5str") return new DERIA5String(param[key]);
	if (key == "utctime") return new DERUTCTime(param[key]);
	if (key == "gentime") return new DERGeneralizedTime(param[key]);

	if (key == "seq") {
		let paramList = /** @type {Array<Object>} */ ( param[key] );
		/** @type {Array<ASN1Object>} */ let a = [];
		for (let i = 0; i < paramList.length; i++) {
			let asn1Obj = newObject(paramList[i]);
			a.push(asn1Obj);
		}
		return new DERSequence({ 'array': a });
	}

	if (key == "set") {
		let paramList = /** @type {Array<Object>} */ ( param[key] );
		/** @type {Array<ASN1Object>} */ let a = [];
		for (let i = 0; i < paramList.length; i++) {
			let asn1Obj = newObject(paramList[i]);
			a.push(asn1Obj);
		}
		return new DERSet({ 'array': a });
	}

	if (key == "tag") {
		let tagParam = param[key];
		if (Object.prototype.toString.call(tagParam) === '[object Array]' &&
			tagParam.length == 3) {
			let obj = newObject(/** @type {Object} */ ( tagParam[2] ));
			return new DERTaggedObject({
				'tag': tagParam[0],
				'explicit': tagParam[1],
				'obj': obj
			});
		} else {
			/** @dict */ let newParam = {};
			if (tagParam['explicit'] !== undefined)
				newParam['explicit'] = tagParam['explicit'];
			if (tagParam['tag'] !== undefined)
				newParam['tag'] = tagParam['tag'];
			if (tagParam['obj'] === undefined)
				throw "obj shall be specified for 'tag'.";
			newParam['obj'] = newObject(/** @type {Object} */ ( tagParam['obj'] ));
			return new DERTaggedObject(newParam);
		}
	}

	return null;
}

/**
 * get encoded hexadecimal string of ASN1Object specifed by JSON parameters
 * @param {Object} param JSON parameter to generate ASN1Object
 * @return {string} hexadecimal string of ASN1Object
 * @description
 * As for ASN.1 object representation of JSON object,
 * please see {@link newObject}.
 * @example
 * jsonToASN1HEX({'prnstr': 'aaa'}); 
 */
export function jsonToASN1HEX(param) {
	let asn1Obj = newObject(param);
	return asn1Obj.getEncodedHex();
}

/**
 * get dot noted oid number string from hexadecimal value of OID
 * @param {string} hex hexadecimal value of object identifier
 * @return {string} dot noted string of object identifier
 * @description
 * This static method converts from hexadecimal string representation of 
 * ASN.1 value of object identifier to oid number string.
 * @example
 * oidHexToInt('550406') &rarr; "2.5.4.6"
 */
export function oidHexToInt(hex) {
	let i01 = parseInt(hex.substr(0, 2), 16);
	let i0 = Math.floor(i01 / 40);
	let i1 = i01 % 40;
	let s = i0 + "." + i1;

	let binbuf = "";
	for (let i = 2; i < hex.length; i += 2) {
		let value = parseInt(hex.substr(i, 2), 16);
		let bin = ("00000000" + value.toString(2)).slice(- 8);
		binbuf = binbuf + bin.substr(1, 7);
		if (bin.substr(0, 1) == "0") {
			let bi = new BigInteger(binbuf, 2);
			s = s + "." + bi.toString(10);
			binbuf = "";
		}
	}

	return s;
}

/**
 * @param {number} i 
 * @returns {string}
 */
function itox(i) {
	let h = i.toString(16);
	if (h.length == 1) h = '0' + h;
	return h;
}

/**
 * @param {string} roid 
 * @returns {string}
 */
function roidtox(roid) {
	let h = '';
	let bi = new BigInteger(roid, 10);
	let b = bi.toString(2);
	let padLen = 7 - b.length % 7;
	if (padLen == 7) padLen = 0;
	let bPad = '';
	for (let i = 0; i < padLen; i++) bPad += '0';
	b = bPad + b;
	for (let i = 0; i < b.length - 1; i += 7) {
		let b8 = b.substr(i, 7);
		if (i != b.length - 7) b8 = '1' + b8;
		h += itox(parseInt(b8, 2));
	}
	return h;
}

/**
 * get hexadecimal value of object identifier from dot noted oid value
 * @param {string} oidString dot noted string of object identifier
 * @return {string} hexadecimal value of object identifier
 * @description
 * This static method converts from object identifier value string.
 * to hexadecimal string representation of it.
 * @example
 * oidIntToHex("2.5.4.6") &rarr; "550406"
 */
export function oidIntToHex(oidString) {
	if (!oidString.match(/^[0-9.]+$/)) {
		throw "malformed oid string: " + oidString;
	}
	let h = '';
	let a = oidString.split('.');
	let i0 = parseInt(a[0], 10) * 40 + parseInt(a[1], 10);
	h += itox(i0);
	a.splice(0, 2);
	for (let i = 0; i < a.length; i++) {
		h += roidtox(a[i]);
	}
	return h;
}

/**
 * base class for ASN.1 DER encoder object
 * @property {boolean} isModified flag whether internal data was changed
 * @property {string} hTLV hexadecimal string of ASN.1 TLV
 * @property {string} hT hexadecimal string of ASN.1 TLV tag(T)
 * @property {string} hL hexadecimal string of ASN.1 TLV length(L)
 * @property {string} hV hexadecimal string of ASN.1 TLV value(V)
 * @description
 */
export class ASN1Object {
	constructor() {
		/** @protected */ this.isModified = true;
		/** @protected @type {string | null} */ this.hTLV = null;
		/** @protected @type {string} */ this.hT = '00';
		/** @protected @type {string} */ this.hL = '00';
		/** @protected @type {string} */ this.hV = '';
	}

    /**
     * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
     * @return {string} hexadecimal string of ASN.1 TLV length(L)
     */
	getLengthHexFromValue() {
		if (typeof this.hV == "undefined" || this.hV == null) {
			throw "this.hV is null or undefined.";
		}
		if (this.hV.length % 2 == 1) {
			throw "value hex must be even length: n=" + this.hV.length + ",v=" + this.hV;
		}
		let n = this.hV.length / 2;
		let hN = n.toString(16);
		if (hN.length % 2 == 1) {
			hN = "0" + hN;
		}
		if (n < 128) {
			return hN;
		} else {
			let hNlen = hN.length / 2;
			if (hNlen > 15) {
				throw "ASN.1 length too long to represent by 8x: n = " + n.toString(16);
			}
			let head = 128 + hNlen;
			return head.toString(16) + hN;
		}
	}

    /**
     * get hexadecimal string of ASN.1 TLV bytes
     * @return {string} hexadecimal string of ASN.1 TLV
     */
	getEncodedHex() {
		if (this.hTLV == null || this.isModified) {
			this.hV = this.getFreshValueHex();
			this.hL = this.getLengthHexFromValue();
			this.hTLV = this.hT + this.hL + this.hV;
			this.isModified = false;
			//alert("first time: " + this.hTLV);
		}
		return this.hTLV;
	}

    /**
     * get hexadecimal string of ASN.1 TLV value(V) bytes
     * @return {string} hexadecimal string of ASN.1 TLV value(V) bytes
     */
	getValueHex() {
		this.getEncodedHex();
		return this.hV;
	}

	getFreshValueHex() {
		return '';
	}
}

/**
 * base class for ASN.1 DER string classes
 * @abstract
 * @property {string} s internal string of value
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
export class DERAbstractString extends ASN1Object {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		super();

		/** @protected @type {string | null} */ this.s = null;
		/** @protected @type {string | null} */ this.hV = null;

		if (typeof params != "undefined") {
			if (typeof params == "string") {
				this.setString(params);
			} else if (typeof params['str'] != "undefined") {
				this.setString(String(params['str']));
			} else if (typeof params['hex'] != "undefined") {
				this.setStringHex(String(params['hex']));
			}
		}	
	}

    /**
     * get string value of this string object
     * @return {string | null} string value of this string object
     */
	getString() {
		return this.s;
	}

    /**
     * set value by a string
     * @param {string} newS value by a string to set
     * @description
     * This method set value by string. <br/>
     * NOTE: This method assumes that the argument string is
     * UTF-8 encoded even though ASN.1 primitive 
     * such as IA5String or PrintableString doesn't
     * support all of UTF-8 characters.
     * @example
     * o = new DERIA5String();
     * o.setString("abc");
     * o.setString("あいう");
     */
	setString(newS) {
		this.hTLV = null;
		this.isModified = true;
		this.s = newS;
		this.hV = utf8tohex(this.s).toLowerCase();
	}

    /**
     * set value by a hexadecimal string
     * @param {string} newHexString value by a hexadecimal string to set
     */
	setStringHex(newHexString) {
		this.hTLV = null;
		this.isModified = true;
		this.s = null;
		this.hV = newHexString;
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * base class for ASN.1 DER Generalized/UTCTime class
 * @abstract
 */
export class DERAbstractTime extends ASN1Object {
	constructor() {
		super();
	
		/** @protected @type {string | null} */ this.s = null;
		/** @protected @type {Date | null} */ this.date = null;
	}

	/**
	 * @private
	 * @param {Date} d 
	 * @returns {Date}
	 */
	static localDateToUTC(d) {
		let utc = d.getTime() + (d.getTimezoneOffset() * 60000);
		let utcDate = new Date(utc);
		return utcDate;
	}

    /**
     * format date string by Data object
	 * @private
     * @param {Date} dateObject 
     * @param {string} type 'utc' or 'gen'
     * @param {boolean=} withMillis flag for with millisections or not
     * @description
     * 'withMillis' flag is supported from asn1 1.0.6.
     */
	formatDate(dateObject, type, withMillis) {
		let d = DERAbstractTime.localDateToUTC(dateObject);
		let year = String(d.getFullYear());
		if (type == 'utc') year = year.substr(2, 2);
		let month = DERAbstractTime.zeroPadding(String(d.getMonth() + 1), 2);
		let day = DERAbstractTime.zeroPadding(String(d.getDate()), 2);
		let hour = DERAbstractTime.zeroPadding(String(d.getHours()), 2);
		let min = DERAbstractTime.zeroPadding(String(d.getMinutes()), 2);
		let sec = DERAbstractTime.zeroPadding(String(d.getSeconds()), 2);
		let s = year + month + day + hour + min + sec;
		if (withMillis === true) {
			let millis = d.getMilliseconds();
			if (millis != 0) {
				let sMillis = DERAbstractTime.zeroPadding(String(millis), 3);
				sMillis = sMillis.replace(/[0]+$/, "");
				s = s + "." + sMillis;
			}
		}
		return s + "Z";
	}

	/**
	 * @private
	 * @param {string} s 
	 * @param {number} len 
	 */
	static zeroPadding(s, len) {
		if (s.length >= len) return s;
		return new Array(len - s.length + 1).join('0') + s;
	}

    /**
     * get string value of this string object
     * @return {string | null} string value of this time object
     */
	getString() {
		return this.s;
	}

    /**
     * set value by a string
     * @param {string} newS value by a string to set such like "130430235959Z"
     */
	setString(newS) {
		this.hTLV = null;
		this.isModified = true;
		this.s = newS;
		this.hV = stohex(newS);
	}

    /**
     * set value by a Date object
     * @param {number} year year of date (ex. 2013)
     * @param {number} month month of date between 1 and 12 (ex. 12)
     * @param {number} day day of month
     * @param {number} hour hours of date
     * @param {number} min minutes of date
     * @param {number} sec seconds of date
     */
	setByDateValue(year, month, day, hour, min, sec) {
		let dateObject = new Date(Date.UTC(year, month - 1, day, hour, min, sec, 0));
		this.setByDate(dateObject);
	}

	/**
     * set value by a Date object<br/>
	 * @abstract
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     */
	setByDate(dateObject) {}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * base class for ASN.1 DER structured class
 * @abstract
 * @property {Array<ASN1Object>} asn1Array internal array of ASN1Object
 */
export class DERAbstractStructured extends ASN1Object {
	/**
	 * @param {Object=} params
	 */
	constructor(params) {
		super();

		/** @protected @type {Array<ASN1Object>} */ this.asn1Array = [];

		if (typeof params != "undefined") {
			if (typeof params['array'] != "undefined") {
				this.asn1Array = /** @type {Array<ASN1Object>} */ ( params['array'] );
			}
		}
	}

    /**
     * set value by array of ASN1Object
     * @param {Array<ASN1Object>} asn1ObjectArray array of ASN1Object to set
     */
	setByASN1ObjectArray(asn1ObjectArray) {
		this.hTLV = null;
		this.isModified = true;
		this.asn1Array = asn1ObjectArray;
	}

    /**
     * append an ASN1Object to internal array
     * @param {ASN1Object} asn1Object to add
     */
	appendASN1Object(asn1Object) {
		this.hTLV = null;
		this.isModified = true;
		this.asn1Array.push(asn1Object);
	}
}

/**
 * class for ASN.1 DER Boolean
 */
export class DERBoolean extends ASN1Object {
	/**
	 * @param {Object=} params
	 */
	constructor(params) {
		super();

		this.hT = "01";
		this.hTLV = "0101ff";

		if (typeof params != "undefined") {
			if (typeof params['bool'] != "undefined") {
				this.setByBoolean(params['bool']);
			} else if (typeof params == "boolean") {
				this.setByBoolean(params ? true : false);
			} else if (typeof params['hex'] != "undefined") {
				this.setValueHex(String(params['hex']));
			}
		}
	}

    /**
     * set value by boolean value
     * @param {boolean} boolValue boolean value to set
     */
	setByBoolean(boolValue) {
		this.hV = boolValue ? 'ff' : '00';
		this.hTLV = '0101' + this.hV;
	}

    /**
     * set value by integer value
     * @param {string} newHexString hexadecimal string of integer value
     * @description
     * <br/>
     * NOTE: Value shall be represented by minimum octet length of
     * two's complement representation.
     * @example
     * new DERBoolean(true);
     * new DERBoolean({'bool': true});
     * new DERBoolean({'hex': 'ff'});
     */
	setValueHex(newHexString) {
		this.hTLV = null;
		this.isModified = true;
		this.hV = newHexString;
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * class for ASN.1 DER Integer
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>int - specify initial ASN.1 value(V) by integer value</li>
 * <li>bigint - specify initial ASN.1 value(V) by BigInteger object</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
export class DERInteger extends ASN1Object {
	/**
	 * @param {(Object | number)=} params
	 */
	constructor(params) {
		super();

		this.hT = "02";

		if (typeof params != "undefined") {
			if (typeof params['bigint'] != "undefined") {
				this.setByBigInteger(params['bigint']);
			} else if (typeof params['int'] != "undefined") {
				this.setByInteger(params['int']);
			} else if (typeof params == "number") {
				this.setByInteger(params);
			} else if (typeof params['hex'] != "undefined") {
				this.setValueHex(String(params['hex']));
			}
		}
	}

    /**
     * set value by Tom Wu's BigInteger object
     * @param {BigInteger} bigIntegerValue to set
     */
	setByBigInteger(bigIntegerValue) {
		this.hTLV = null;
		this.isModified = true;
		this.hV = bigIntToMinTwosComplementsHex(bigIntegerValue);
	}

    /**
     * set value by integer value
     * @param {number} intValue integer value to set
     */
	setByInteger(intValue) {
		let bi = new BigInteger(String(intValue), 10);
		this.setByBigInteger(bi);
	}

    /**
     * set value by integer value
     * @param {string} newHexString hexadecimal string of integer value
     * @description
     * <br/>
     * NOTE: Value shall be represented by minimum octet length of
     * two's complement representation.
     * @example
     * new DERInteger(123);
     * new DERInteger({'int': 123});
     * new DERInteger({'hex': '1fad'});
     */
	setValueHex(newHexString) {
		this.hTLV = null;
		this.isModified = true;
		this.hV = newHexString;
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * class for ASN.1 DER encoded BitString primitive
 * @description 
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>bin - specify binary string (ex. '10111')</li>
 * <li>array - specify array of boolean (ex. [true,false,true,true])</li>
 * <li>hex - specify hexadecimal string of ASN.1 value(V) including unused bits</li>
 * <li>obj - specify {@link newObject} 
 * argument for "BitString encapsulates" structure.</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: 'obj' parameter have been supported since
 * asn1 1.0.11, jsrsasign 6.1.1 (2016-Sep-25).<br/>
 * @example
 * // default constructor
 * o = new DERBitString();
 * // initialize with binary string
 * o = new DERBitString({bin: "1011"});
 * // initialize with boolean array
 * o = new DERBitString({array: [true,false,true,true]});
 * // initialize with hexadecimal string (04 is unused bits)
 * o = new DEROctetString({hex: "04bac0"});
 * // initialize with ASN1Util.newObject argument for encapsulated
 * o = new DERBitString({obj: {seq: [{int: 3}, {prnstr: 'aaa'}]}});
 * // above generates a ASN.1 data like this:
 * // BIT STRING, encapsulates {
 * //   SEQUENCE {
 * //     INTEGER 3
 * //     PrintableString 'aaa'
 * //     }
 * //   } 
 */
export class DERBitString extends ASN1Object {
	/**
	 * @param {(Object | string)=} params
	 */
	constructor(params) {
		if (params !== undefined && typeof params['obj'] !== "undefined") {
			let o = newObject(params['obj']);
			params['hex'] = "00" + o.getEncodedHex();
		}

		super();

		this.hT = "03";

		if (typeof params != "undefined") {
			if (typeof params == "string" && params.toLowerCase().match(/^[0-9a-f]+$/)) {
				this.setHexValueIncludingUnusedBits(params);
			} else if (typeof params['hex'] != "undefined") {
				this.setHexValueIncludingUnusedBits(params['hex']);
			} else if (typeof params['bin'] != "undefined") {
				this.setByBinaryString(params['bin']);
			} else if (typeof params['array'] != "undefined") {
				this.setByBooleanArray(params['array']);
			}
		}
	}

    /**
     * set ASN.1 value(V) by a hexadecimal string including unused bits
     * @param {string} newHexStringIncludingUnusedBits
     */
	setHexValueIncludingUnusedBits(newHexStringIncludingUnusedBits) {
		this.hTLV = null;
		this.isModified = true;
		this.hV = newHexStringIncludingUnusedBits;
	}

    /**
     * set ASN.1 value(V) by unused bit and hexadecimal string of value
     * @param {number} unusedBits
     * @param {string} hValue
     */
	setUnusedBitsAndHexValue(unusedBits, hValue) {
		if (unusedBits < 0 || 7 < unusedBits) {
			throw "unused bits shall be from 0 to 7: u = " + unusedBits;
		}
		let hUnusedBits = "0" + unusedBits;
		this.hTLV = null;
		this.isModified = true;
		this.hV = hUnusedBits + hValue;
	}

    /**
     * set ASN.1 DER BitString by binary string<br/>
     * @param {string} binaryString binary value string (i.e. '10111')
     * @description
     * Its unused bits will be calculated automatically by length of 
     * 'binaryValue'. <br/>
     * NOTE: Trailing zeros '0' will be ignored.
     * @example
     * o = new DERBitString();
     * o.setByBooleanArray("01011");
     */
	setByBinaryString(binaryString) {
		binaryString = binaryString.replace(/0+$/, '');
		let unusedBits = 8 - binaryString.length % 8;
		if (unusedBits == 8) unusedBits = 0;
		for (let i = 0; i <= unusedBits; i++) {
			binaryString += '0';
		}
		let h = '';
		for (let i = 0; i < binaryString.length - 1; i += 8) {
			let b = binaryString.substr(i, 8);
			let x = parseInt(b, 2).toString(16);
			if (x.length == 1) x = '0' + x;
			h += x;
		}
		this.hTLV = null;
		this.isModified = true;
		this.hV = '0' + unusedBits + h;
	}

    /**
     * set ASN.1 TLV value(V) by an array of boolean<br/>
     * @param {Array<boolean>} booleanArray array of boolean (ex. [true, false, true])
     * @description
     * NOTE: Trailing falses will be ignored in the ASN.1 DER Object.
     * @example
     * o = new DERBitString();
     * o.setByBooleanArray([false, true, false, true, true]);
     */
	setByBooleanArray(booleanArray) {
		let s = '';
		for (let i = 0; i < booleanArray.length; i++) {
			if (booleanArray[i] == true) {
				s += '1';
			} else {
				s += '0';
			}
		}
		this.setByBinaryString(s);
	}

    /**
     * generate an array of falses with specified length<br/>
     * @param {number} nLength length of array to generate
     * @return {Array<boolean>} array of boolean falses
     * @description
     * This static method may be useful to initialize boolean array.
     * @example
     * o = new DERBitString();
     * o.newFalseArray(3) &rarr; [false, false, false]
     */
	static newFalseArray(nLength) {
		let a = new Array(nLength);
		for (let i = 0; i < nLength; i++) {
			a[i] = false;
		}
		return a;
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * class for ASN.1 DER OctetString<br/>
 * @description
 * This class provides ASN.1 OctetString simple type.<br/>
 * Supported "params" attributes are:
 * <ul>
 * <li>str - to set a string as a value</li>
 * <li>hex - to set a hexadecimal string as a value</li>
 * <li>obj - to set a encapsulated ASN.1 value by JSON object 
 * which is defined in {@link newObject}</li>
 * </ul>
 * NOTE: A parameter 'obj' have been supported 
 * for "OCTET STRING, encapsulates" structure.
 * since asn1 1.0.11, jsrsasign 6.1.1 (2016-Sep-25).
 * @example
 * // default constructor
 * o = new DEROctetString();
 * // initialize with string
 * o = new DEROctetString({str: "aaa"});
 * // initialize with hexadecimal string
 * o = new DEROctetString({hex: "616161"});
 * // initialize with ASN1Util.newObject argument 
 * o = new DEROctetString({obj: {seq: [{int: 3}, {prnstr: 'aaa'}]}});
 * // above generates a ASN.1 data like this:
 * // OCTET STRING, encapsulates {
 * //   SEQUENCE {
 * //     INTEGER 3
 * //     PrintableString 'aaa'
 * //     }
 * //   } 
 */
export class DEROctetString extends DERAbstractString {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		if (params !== undefined && typeof params['obj'] !== "undefined") {
			let o = newObject(params['obj']);
			params['hex'] = o.getEncodedHex();
		}

		super(params);

		this.hT = "04";
	}
}

/**
 * class for ASN.1 DER Null
 */
export class DERNull extends ASN1Object {
	/**
	 * @param {*=} params 
	 */
	constructor(params) {
		super();

		this.hT = "05";
		this.hTLV = "0500";
	}
}

/**
 * class for ASN.1 DER ObjectIdentifier
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>oid - specify initial ASN.1 value(V) by a oid string (ex. 2.5.4.13)</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
export class DERObjectIdentifier extends ASN1Object {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'oid': '2.5.4.5'})
	 */
	constructor(params) {
		super();

		this.hT = "06";
		
		if (params !== undefined) {
			if (typeof params === "string") {
				if (params.match(/^[0-2].[0-9.]+$/)) {
					this.setValueOidString(params);
				} else {
					this.setValueName(params);
				}
			} else if (params['oid'] !== undefined) {
				this.setValueOidString(String(params['oid']));
			} else if (params['hex'] !== undefined) {
				this.setValueHex(String(params['hex']));
			} else if (params['name'] !== undefined) {
				this.setValueName(String(params['name']));
			}
		}
	}

    /**
     * set value by a hexadecimal string
     * @param {string} newHexString hexadecimal value of OID bytes
     */
	setValueHex(newHexString) {
		this.hTLV = null;
		this.isModified = true;
		//this.s = null;
		this.hV = newHexString;
	}

    /**
     * set value by a OID string<br/>
     * @param {string} oidString OID string (ex. 2.5.4.13)
     * @example
     * o = new DERObjectIdentifier();
     * o.setValueOidString("2.5.4.13");
     */
	setValueOidString(oidString) {
		if (!oidString.match(/^[0-9.]+$/)) {
			throw "malformed oid string: " + oidString;
		}
		let h = '';
		let a = oidString.split('.');
		let i0 = parseInt(a[0], 10) * 40 + parseInt(a[1], 10);
		h += itox(i0);
		a.splice(0, 2);
		for (let i = 0; i < a.length; i++) {
			h += roidtox(a[i]);
		}
		this.hTLV = null;
		this.isModified = true;
		//this.s = null;
		this.hV = h;
	}

    /**
     * set value by a OID name
     * @param {string} oidName OID name (ex. 'serverAuth')
     * @description
     * OID name shall be defined in 'name2oidList'.
     * Otherwise raise error.
     * @example
     * o = new DERObjectIdentifier();
     * o.setValueName("serverAuth");
     */
	setValueName(oidName) {
		let oid = name2oid(oidName);
		if (oid !== '') {
			this.setValueOidString(oid);
		} else {
			throw "DERObjectIdentifier oidName undefined: " + oidName;
		}
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * class for ASN.1 DER Enumerated
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>int - specify initial ASN.1 value(V) by integer value</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 * @example
 * new DEREnumerated(123);
 * new DEREnumerated({int: 123});
 * new DEREnumerated({hex: '1fad'});
 */
export class DEREnumerated extends ASN1Object {
	/**
	 * @param {(* | number)=} params 
	 */
	constructor(params) {
		super();

		this.hT = "0a";

		if (typeof params != "undefined") {
			if (typeof params['int'] != "undefined") {
				this.setByInteger(params['int']);
			} else if (typeof params == "number") {
				this.setByInteger(params);
			} else if (typeof params['hex'] != "undefined") {
				this.setValueHex(String(params['hex']));
			}
		}
	}

    /**
     * set value by Tom Wu's BigInteger object
     * @param {BigInteger} bigIntegerValue to set
     */
	setByBigInteger(bigIntegerValue) {
		this.hTLV = null;
		this.isModified = true;
		this.hV = bigIntToMinTwosComplementsHex(bigIntegerValue);
	}

    /**
     * set value by integer value
     * @param {number} intValue integer value to set
     */
	setByInteger(intValue) {
		let bi = new BigInteger(String(intValue), 10);
		this.setByBigInteger(bi);
	}

    /**
     * set value by integer value
     * @param {string} newHexString hexadecimal string of integer value
     * @description
     * <br/>
     * NOTE: Value shall be represented by minimum octet length of
     * two's complement representation.
     */
	setValueHex(newHexString) {
		this.hV = newHexString;
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}

/**
 * class for ASN.1 DER UTF8String
 * @description
 */
export class DERUTF8String extends DERAbstractString {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		super(params);

		this.hT = "0c";
	}
}

/**
 * class for ASN.1 DER NumericString
 * @description
 */
export class DERNumericString extends DERAbstractString {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		super(params);

		this.hT = "12";
	}
}

/**
 * class for ASN.1 DER PrintableString
 * @description
 */
export class DERPrintableString extends DERAbstractString {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		super(params);

		this.hT = "13";
	}
}

/**
 * class for ASN.1 DER TeletexString
 * @description
 */
export class DERTeletexString extends DERAbstractString {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		super(params);

		this.hT = "14";
	}
}

/**
 * class for ASN.1 DER IA5String
 * @description
 */
export class DERIA5String extends DERAbstractString {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': 'aaa'})
	 */
	constructor(params) {
		super(params);

		this.hT = "16";
	}
}

/**
 * class for ASN.1 DER UTCTime
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string (ex.'130430235959Z')</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * <li>date - specify Date object.</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 * <h4>EXAMPLES</h4>
 * @example
 * d1 = new DERUTCTime();
 * d1.setString('130430125959Z');
 *
 * d2 = new DERUTCTime({'str': '130430125959Z'});
 * d3 = new DERUTCTime({'date': new Date(Date.UTC(2015, 0, 31, 0, 0, 0, 0))});
 * d4 = new DERUTCTime('130430125959Z');
 */
export class DERUTCTime extends DERAbstractTime {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': '130430235959Z'})
	 */
	constructor(params) {
		super();

		this.hT = "17";
		/** @type {string} */ this.s;

		if (params !== undefined) {
			if (params['str'] !== undefined) {
				this.setString(params['str']);
			} else if (typeof params == "string" && params.match(/^[0-9]{12}Z$/)) {
				this.setString(params);
			//} else if (params['hex'] !== undefined) {
			//	this.setStringHex(String(params['hex']));
			} else if (params['date'] !== undefined) {
				this.setByDate(params['date']);
			}
		}
	}

    /**
     * set value by a Date object<br/>
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     * @example
     * o = new DERUTCTime();
     * o.setByDate(new Date("2016/12/31"));
     */
	setByDate(dateObject) {
		this.hTLV = null;
		this.isModified = true;
		this.date = dateObject;
		this.s = this.formatDate(this.date, 'utc');
		this.hV = stohex(this.s);
	}

	/** @override */
	getFreshValueHex() {
		if (typeof this.date == "undefined" && typeof this.s == "undefined") {
			this.date = new Date();
			this.s = this.formatDate(this.date, 'utc');
			this.hV = stohex(this.s);
		}
		return this.hV;
	}
}

/**
 * class for ASN.1 DER GeneralizedTime
 * @property {boolean} withMillis flag to show milliseconds or not
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>str - specify initial ASN.1 value(V) by a string (ex.'20130430235959Z')</li>
 * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
 * <li>date - specify Date object.</li>
 * <li>millis - specify flag to show milliseconds (from 1.0.6)</li>
 * </ul>
 * NOTE1: 'params' can be omitted.
 * NOTE2: 'withMillis' property is supported from asn1 1.0.6.
 */
export class DERGeneralizedTime extends DERAbstractTime {
	/**
	 * @param {(Object | string)=} params dictionary of parameters (ex. {'str': '20130430235959Z'})
	 */
	constructor(params) {
		super();

		this.hT = "18";
		this.withMillis = false;
		/** @type {string} */ this.s;

		if (params !== undefined) {
			if (params['str'] !== undefined) {
				this.setString(params['str']);
			} else if (typeof params == "string" && params.match(/^[0-9]{14}Z$/)) {
				this.setString(params);
			//} else if (params['hex'] !== undefined) {
			//	this.setStringHex(String(params['hex']));
			} else if (params['date'] !== undefined) {
				this.setByDate(params['date']);
			}
			if (params['millis'] === true) {
				this.withMillis = true;
			}
		}
	}

    /**
     * set value by a Date object
     * @param {Date} dateObject Date object to set ASN.1 value(V)
     * @example
     * When you specify UTC time, use 'Date.UTC' method like this:<br/>
     * o1 = new DERUTCTime();
     * o1.setByDate(date);
     *
     * date = new Date(Date.UTC(2015, 0, 31, 23, 59, 59, 0)); #2015JAN31 23:59:59
     */
	setByDate(dateObject) {
		this.hTLV = null;
		this.isModified = true;
		this.date = dateObject;
		this.s = this.formatDate(this.date, 'gen', this.withMillis);
		this.hV = stohex(this.s);
	}

	/** @override */
	getFreshValueHex() {
		if (this.date === undefined && this.s === undefined) {
			this.date = new Date();
			this.s = this.formatDate(this.date, 'gen', this.withMillis);
			this.hV = stohex(this.s);
		}
		return this.hV;
	}
}

/**
 * class for ASN.1 DER Sequence
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>array - specify array of ASN1Object to set elements of content</li>
 * </ul>
 * NOTE: 'params' can be omitted.
 */
export class DERSequence extends DERAbstractStructured {
	/**
	 * @param {Object=} params
	 */
	constructor(params) {
		super(params);

		this.hT = "30";
	}

	/** @override */
	getFreshValueHex() {
		let h = '';
		for (let i = 0; i < this.asn1Array.length; i++) {
			let asn1Obj = this.asn1Array[i];
			h += asn1Obj.getEncodedHex();
		}
		this.hV = h;
		return this.hV;
	}
}

/**
 * class for ASN.1 DER Set
 * @description
 * <br/>
 * As for argument 'params' for constructor, you can specify one of
 * following properties:
 * <ul>
 * <li>array - specify array of ASN1Object to set elements of content</li>
 * <li>sortflag - flag for sort (default: true). ASN.1 BER is not sorted in 'SET OF'.</li>
 * </ul>
 * NOTE1: 'params' can be omitted.<br/>
 * NOTE2: sortflag is supported since 1.0.5.
 */
export class DERSet extends DERAbstractStructured {
	/**
	 * @param {Object=} params
	 */
	constructor(params) {
		super(params);

		this.hT = "31";
		this.sortFlag = true; // item shall be sorted only in ASN.1 DER

		if (typeof params != "undefined") {
			if (typeof params['sortflag'] != "undefined" &&
				params['sortflag'] == false)
				this.sortFlag = false;
		}
	}

	/** @override */
	getFreshValueHex() {
		let a = new Array();
		for (let i = 0; i < this.asn1Array.length; i++) {
			let asn1Obj = this.asn1Array[i];
			a.push(asn1Obj.getEncodedHex());
		}
		if (this.sortFlag == true) a.sort();
		this.hV = a.join('');
		return this.hV;
	}
}

/**
 * class for ASN.1 DER TaggedObject
 * @description
 * <br/>
 * Parameter 'tagNoNex' is ASN.1 tag(T) value for this object.
 * For example, if you find '[1]' tag in a ASN.1 dump, 
 * 'tagNoHex' will be 'a1'.
 * <br/>
 * As for optional argument 'params' for constructor, you can specify *ANY* of
 * following properties:
 * <ul>
 * <li>explicit - specify true if this is explicit tag otherwise false 
 *     (default is 'true').</li>
 * <li>tag - specify tag (default is 'a0' which means [0])</li>
 * <li>obj - specify ASN1Object which is tagged</li>
 * </ul>
 * @example
 * d1 = new DERUTF8String({'str':'a'});
 * d2 = new DERTaggedObject({'obj': d1});
 * hex = d2.getEncodedHex();
 */
export class DERTaggedObject extends ASN1Object {
	/**
	 * @param {Object} params 
	 */
	constructor(params) {
		super();

		this.hT = "a0";
		/** @type {string | null} */ this.hV = '';
		/** @type {boolean} */ this.isExplicit = true;
		/** @type {ASN1Object | null} */ this.asn1Object = null;

		if (typeof params != "undefined") {
			if (typeof params['tag'] != "undefined") {
				this.hT = String(params['tag']);
			}
			if (typeof params['explicit'] != "undefined") {
				this.isExplicit = params['explicit'] ? true : false;
			}
			if (typeof params['obj'] != "undefined" && params['obj'] instanceof ASN1Object) {
				this.asn1Object = /** @type {ASN1Object} */ ( params['obj'] );
				this.setASN1Object(this.isExplicit, this.hT, this.asn1Object);
			}
		}
	}

    /**
     * set value by an ASN1Object
     * @param {boolean} isExplicitFlag flag for explicit/implicit tag
     * @param {string} tagNoHex hexadecimal string of ASN.1 tag
     * @param {ASN1Object} asn1Object ASN.1 to encapsulate
     */
	setASN1Object(isExplicitFlag, tagNoHex, asn1Object) {
		this.hT = tagNoHex;
		this.isExplicit = isExplicitFlag;
		this.asn1Object = asn1Object;
		if (this.isExplicit) {
			this.hV = this.asn1Object.getEncodedHex();
			this.hTLV = null;
			this.isModified = true;
		} else {
			this.hV = null;
			this.hTLV = asn1Object.getEncodedHex();
			this.hTLV = this.hTLV.replace(/^../, tagNoHex);
			this.isModified = false;
		}
	}

	/** @override */
	getFreshValueHex() {
		return this.hV;
	}
}
