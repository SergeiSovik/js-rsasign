/*
 * asn1hex.js - Hexadecimal represented ASN.1 string library
 *
 * Original work Copyright (c) 2010-2017 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { oidHexToInt, ASN1Object } from "./asn1-1.0.js"
import { isHex, hextoutf8 } from "./base64x-1.1.js"
import { oid2name } from "./asn1oid.js"
import { BigInteger } from "./../../js-bn/modules/jsbn.js"

/*
 * MEMO:
 *   f('3082025b02...', 2) ... 82025b ... 3bytes
 *   f('020100', 2) ... 01 ... 1byte
 *   f('0203001...', 2) ... 03 ... 1byte
 *   f('02818003...', 2) ... 8180 ... 2bytes
 *   f('3080....0000', 2) ... 80 ... -1
 *
 *   Requirements:
 *   - ASN.1 type octet length MUST be 1. 
 *     (i.e. ASN.1 primitives like SET, SEQUENCE, INTEGER, OCTETSTRING ...)
 */

/**
 * ASN.1 DER encoded hexadecimal string utility module
 * @description
 * This module provides a parser for hexadecimal string of
 * DER encoded ASN.1 binary data.
 * Here are major methods of this module.
 * <ul>
 * <li><b>ACCESS BY POSITION</b>
 *   <ul>
 *   <li>{@link getTLV} - get ASN.1 TLV at specified position</li>
 *   <li>{@link getV} - get ASN.1 V at specified position</li>
 *   <li>{@link getVlen} - get integer ASN.1 L at specified position</li>
 *   <li>{@link getVidx} - get ASN.1 V position from its ASN.1 TLV position</li>
 *   <li>{@link getL} - get hexadecimal ASN.1 L at specified position</li>
 *   <li>{@link getLblen} - get byte length for ASN.1 L(length) bytes</li>
 *   </ul>
 * </li>
 * <li><b>ACCESS FOR CHILD ITEM</b>
 *   <ul>
 *   <li>{@link getNthChildIndex_AtObj} - get nth child index at specified position</li>
 *   <li>{@link getPosArrayOfChildren_AtObj} - get indexes of children</li>
 *   <li>{@link getPosOfNextSibling_AtObj} - get position of next sibling</li>
 *   </ul>
 * </li>
 * <li><b>ACCESS NESTED ASN.1 STRUCTURE</b>
 *   <ul>
 *   <li>{@link getTLVbyList} - get ASN.1 TLV at specified list index</li>
 *   <li>{@link getVbyList} - get ASN.1 V at specified nth list index with checking expected tag</li>
 *   <li>{@link getIdxbyList} - get index at specified list index</li>
 *   </ul>
 * </li>
 * <li><b>UTILITIES</b>
 *   <ul>
 *   <li>{@link dump} - dump ASN.1 structure</li>
 *   <li>{@link isASN1HEX} - check whether ASN.1 hexadecimal string or not</li>
 *   <li>{@link hextooidstr} - convert hexadecimal string of OID to dotted integer list</li>
 *   </ul>
 * </li>
 * </ul>
 */

/**
 * get byte length for ASN.1 L(length) bytes<br/>
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index
 * @return byte length for ASN.1 L(length) bytes
 * @example
 * getLblen('020100', 0) &rarr; 1 for '01'
 * getLblen('020200', 0) &rarr; 1 for '02'
 * getLblen('02818003...', 0) &rarr; 2 for '8180'
 * getLblen('0282025b03...', 0) &rarr; 3 for '82025b'
 * getLblen('0280020100...', 0) &rarr; -1 for '80' BER indefinite length
 * getLblen('02ffab...', 0) &rarr; -2 for malformed ASN.1 length
 */
export function getLblen(s, idx) {
	if (s.substr(idx + 2, 1) != '8') return 1;
	let i = parseInt(s.substr(idx + 3, 1), 10);
	if (i == 0) return -1;             // length octet '80' indefinite length
	if (0 < i && i < 10) return i + 1; // including '8?' octet;
	return -2;                         // malformed format
}

/**
 * get hexadecimal string for ASN.1 L(length) bytes<br/>
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index to get L of ASN.1 object
 * @return {string} hexadecimal string for ASN.1 L(length) bytes
 */
export function getL(s, idx) {
	let len = getLblen(s, idx);
	if (len < 1) return '';
	return s.substr(idx + 2, len * 2);
}

/**
 * get integer value of ASN.1 length for ASN.1 data<br/>
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index
 * @return ASN.1 L(length) integer value
 */
/*
 getting ASN.1 length value at the position 'idx' of
 hexa decimal string 's'.
 f('3082025b02...', 0) ... 82025b ... ???
 f('020100', 0) ... 01 ... 1
 f('0203001...', 0) ... 03 ... 3
 f('02818003...', 0) ... 8180 ... 128
 */
export function getVblen(s, idx) {
	let hLen, bi;
	hLen = getL(s, idx);
	if (hLen == '') return -1;
	if (hLen.substr(0, 1) === '8') {
		bi = new BigInteger(hLen.substr(2), 16);
	} else {
		bi = new BigInteger(hLen, 16);
	}
	return bi.intValue();
}

/**
 * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index
 */
export function getVidx(s, idx) {
	let l_len = getLblen(s, idx);
	if (l_len < 0) return l_len;
	return idx + (l_len + 1) * 2;
}

/**
 * get hexadecimal string of ASN.1 V(value)<br/>
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index
 * @return {string} hexadecimal string of ASN.1 value.
 */
export function getV(s, idx) {
	let idx1 = getVidx(s, idx);
	let blen = getVblen(s, idx);
	return s.substr(idx1, blen * 2);
}

/**
 * get hexadecimal string of ASN.1 TLV at<br/>
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index
 * @return {string} hexadecimal string of ASN.1 TLV.
 */
export function getTLV(s, idx) {
	return s.substr(idx, 2) + getL(s, idx) + getV(s, idx);
}

// ========== sibling methods ================================

/**
 * get next sibling starting index for ASN.1 object string<br/>
 * @param {string} s hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx string index
 * @return next sibling starting index for ASN.1 object string
 * @example
 * SEQUENCE { INTEGER 3, INTEGER 4 }
 * 3006
 *     020103 :idx=4
 *           020104 :next sibling idx=10
 * getNextSiblingIdx("3006020103020104", 4) & rarr 10
 */
export function getNextSiblingIdx(s, idx) {
	let idx1 = getVidx(s, idx);
	let blen = getVblen(s, idx);
	return idx1 + blen * 2;
}

// ========== children methods ===============================
/**
 * get array of string indexes of child ASN.1 objects<br/>
 * @param {string} h hexadecimal string of ASN.1 DER encoded data
 * @param {number} pos start string index of ASN.1 object
 * @return {Array<number>} array of indexes for childen of ASN.1 objects
 * @description
 * This method returns array of integers for a concatination of ASN.1 objects
 * in a ASN.1 value. As for BITSTRING, one byte of unusedbits is skipped.
 * As for other ASN.1 simple types such as INTEGER, OCTET STRING or PRINTABLE STRING,
 * it returns a array of a string index of its ASN.1 value.<br/>
 * NOTE: Since asn1hex 1.1.7 of jsrsasign 6.1.2, Encapsulated BitString is supported.
 * @example
 * getChildIdx("0203012345", 0) &rArr; [4] // INTEGER 012345
 * getChildIdx("1303616161", 0) &rArr; [4] // PrintableString aaa
 * getChildIdx("030300ffff", 0) &rArr; [6] // BITSTRING ffff (unusedbits=00a)
 * getChildIdx("3006020104020105", 0) &rArr; [4, 10] // SEQUENCE(INT4,INT5)
 */
export function getChildIdx(h, pos) {
	/** @type {Array<number>} */ let a = new Array();
	let p0 = getVidx(h, pos);
	if (h.substr(pos, 2) == "03") {
		a.push(p0 + 2); // BITSTRING value without unusedbits
	} else {
		a.push(p0);
	}

	let blen = getVblen(h, pos);
	let p = p0;
	let k = 0;
	while (1) {
		let pNext = getNextSiblingIdx(h, p);
		if (pNext == null || (pNext - p0 >= (blen * 2))) break;
		if (k >= 200) break;

		a.push(pNext);
		p = pNext;

		k++;
	}

	return a;
}

/**
 * get string index of nth child object of ASN.1 object refered by h, idx<br/>
 * @param {string} h hexadecimal string of ASN.1 DER encoded data
 * @param {number} idx start string index of ASN.1 object
 * @param {number} nth for child
 * @return {number} string index of nth child.
 */
export function getNthChildIdx(h, idx, nth) {
	let a = getChildIdx(h, idx);
	return a[nth];
}

// ========== decendant methods ==============================
/**
 * get string index of nth child object of ASN.1 object refered by h, idx<br/>
 * @param {string} h hexadecimal string of ASN.1 DER encoded data
 * @param {number} currentIndex start string index of ASN.1 object
 * @param {Array<number>} nthList array list of nth
 * @param {string=} checkingTag (OPTIONAL) string of expected ASN.1 tag for nthList 
 * @return {number} string index refered by nthList
 * @description
 * @example
 * The "nthList" is a index list of structured ASN.1 object
 * reference. Here is a sample structure and "nthList"s which
 * refers each objects.
 *
 * SQUENCE               - 
 *   SEQUENCE            - [0]
 *     IA5STRING 000     - [0, 0]
 *     UTF8STRING 001    - [0, 1]
 *   SET                 - [1]
 *     IA5STRING 010     - [1, 0]
 *     UTF8STRING 011    - [1, 1]
 */
export function getIdxbyList(h, currentIndex, nthList, checkingTag) {
	let firstNth, a;
	if (nthList.length == 0) {
		if (checkingTag !== undefined) {
			if (h.substr(currentIndex, 2) !== checkingTag) {
				throw "checking tag doesn't match: " +
				h.substr(currentIndex, 2) + "!=" + checkingTag;
			}
		}
		return currentIndex;
	}
	firstNth = nthList.shift();
	a = getChildIdx(h, currentIndex);
	return getIdxbyList(h, a[firstNth], nthList, checkingTag);
}

/**
 * get ASN.1 TLV by nthList<br/>
 * @param {string} h hexadecimal string of ASN.1 structure
 * @param {number} currentIndex string index to start searching in hexadecimal string "h"
 * @param {Array<number>} nthList array of nth list index
 * @param {string} checkingTag (OPTIONAL) string of expected ASN.1 tag for nthList 
 * @description
 * This static method is to get a ASN.1 value which specified "nthList" position
 * with checking expected tag "checkingTag".
 */
export function getTLVbyList(h, currentIndex, nthList, checkingTag) {
	let idx = getIdxbyList(h, currentIndex, nthList);
	if (idx === undefined) {
		throw "can't find nthList object";
	}
	if (checkingTag !== undefined) {
		if (h.substr(idx, 2) != checkingTag) {
			throw "checking tag doesn't match: " +
			h.substr(idx, 2) + "!=" + checkingTag;
		}
	}
	return getTLV(h, idx);
}

/**
 * get ASN.1 value by nthList<br/>
 * @param {string} h hexadecimal string of ASN.1 structure
 * @param {number} currentIndex string index to start searching in hexadecimal string "h"
 * @param {Array<number>} nthList array of nth list index
 * @param {string=} checkingTag (OPTIONAL) string of expected ASN.1 tag for nthList 
 * @param {boolean=} removeUnusedbits (OPTIONAL) flag for remove first byte for value (DEFAULT false)
 * @description
 * This static method is to get a ASN.1 value which specified "nthList" position
 * with checking expected tag "checkingTag".
 * NOTE: 'removeUnusedbits' flag has been supported since
 * jsrsasign 7.1.14 asn1hex 1.1.10.
 */
export function getVbyList(h, currentIndex, nthList, checkingTag, removeUnusedbits) {
	let idx, v;
	idx = getIdxbyList(h, currentIndex, nthList, checkingTag);

	if (idx === undefined) {
		throw "can't find nthList object";
	}

	v = getV(h, idx);
	if (removeUnusedbits === true) v = v.substr(2);
	return v;
}

/**
 * @param {string} s 
 * @param {number} len 
 * @returns {string}
 */
function zeroPadding(s, len) {
	if (s.length >= len) return s;
	return new Array(len - s.length + 1).join('0') + s;
}

/**
 * get OID string from hexadecimal encoded value<br/>
 * @param {string} hex hexadecmal string of ASN.1 DER encoded OID value
 * @return {string} OID string (ex. '1.2.3.4.567')
 */
export function hextooidstr(hex) {
	let a = [];

	// a[0], a[1]
	let hex0 = hex.substr(0, 2);
	let i0 = parseInt(hex0, 16);
	a[0] = new String(Math.floor(i0 / 40));
	a[1] = new String(i0 % 40);

	// a[2]..a[n]
	let hex1 = hex.substr(2);
	let b = [];
	for (let i = 0; i < hex1.length / 2; i++) {
		b.push(parseInt(hex1.substr(i * 2, 2), 16));
	}
	let c = [];
	let cbin = "";
	for (let i = 0; i < b.length; i++) {
		if (b[i] & 0x80) {
			cbin = cbin + zeroPadding((b[i] & 0x7f).toString(2), 7);
		} else {
			cbin = cbin + zeroPadding((b[i] & 0x7f).toString(2), 7);
			c.push(new String(parseInt(cbin, 2)));
			cbin = "";
		}
	}

	let s = a.join(".");
	if (c.length > 0) s = s + "." + c.join(".");
	return s;
}

/**
 * @param {string} hex 
 * @param {number} limitNumOctet 
 * @returns {string}
 */
function skipLongHex(hex, limitNumOctet) {
	if (hex.length <= limitNumOctet * 2) {
		return hex;
	} else {
		let s = hex.substr(0, limitNumOctet) +
			"..(total " + hex.length / 2 + "bytes).." +
			hex.substr(hex.length - limitNumOctet, limitNumOctet);
		return s;
	}
}

/**
 * get string of simple ASN.1 dump from hexadecimal ASN.1 data<br/>
 * @param {string | ASN1Object} hexOrObj hexadecmal string of ASN.1 data or ASN1Object object
 * @param {Object=} flags associative array of flags for dump (OPTION)
 * @param {number=} idx string index for starting dump (OPTION)
 * @param {string=} indent indent string (OPTION)
 * @return {string} string of simple ASN.1 dump
 * @description
 * This method will get an ASN.1 dump from
 * hexadecmal string of ASN.1 DER encoded data.
 * Here are features:
 * <ul>
 * <li>ommit long hexadecimal string</li>
 * <li>dump encapsulated OCTET STRING (good for X.509v3 extensions)</li>
 * <li>structured/primitive context specific tag support (i.e. [0], [3] ...)</li>
 * <li>automatic decode for implicit primitive context specific tag 
 * (good for X.509v3 extension value)
 *   <ul>
 *   <li>if hex starts '68747470'(i.e. http) it is decoded as utf8 encoded string.</li>
 *   <li>if it is in 'subjectAltName' extension value and is '[2]'(dNSName) tag
 *   value will be encoded as utf8 string</li>
 *   <li>otherwise it shows as hexadecimal string</li>
 *   </ul>
 * </li>
 * </ul>
 * NOTE1: Argument {@link ASN1Object} object is supported since
 * jsrsasign 6.2.4 asn1hex 1.0.8
 * @example
 * // 1) ASN.1 INTEGER
 * dump('0203012345')
 * &darr;
 * INTEGER 012345
 *
 * // 2) ASN.1 Object Identifier
 * dump('06052b0e03021a')
 * &darr;
 * ObjectIdentifier sha1 (1 3 14 3 2 26)
 *
 * // 3) ASN.1 SEQUENCE
 * dump('3006020101020102')
 * &darr;
 * SEQUENCE
 *   INTEGER 01
 *   INTEGER 02
 *
 * // 4) ASN.1 SEQUENCE since jsrsasign 6.2.4
 * o = newObject({seq: [{int: 1}, {int: 2}]});
 * dump(o)
 * &darr;
 * SEQUENCE
 *   INTEGER 01
 *   INTEGER 02
 * // 5) ASN.1 DUMP FOR X.509 CERTIFICATE
 * dump(pemtohex(certPEM))
 * &darr;
 * SEQUENCE
 *   SEQUENCE
 *     [0]
 *       INTEGER 02
 *     INTEGER 0c009310d206dbe337553580118ddc87
 *     SEQUENCE
 *       ObjectIdentifier SHA256withRSA (1 2 840 113549 1 1 11)
 *       NULL
 *     SEQUENCE
 *       SET
 *         SEQUENCE
 *           ObjectIdentifier countryName (2 5 4 6)
 *           PrintableString 'US'
 *             :
 */
export function dump(hexOrObj, flags, idx, indent) {
	let hex = (hexOrObj instanceof ASN1Object) ? hexOrObj.getEncodedHex() : hexOrObj;

	if (flags === undefined) flags = { "ommit_long_octet": 32 };
	if (idx === undefined) idx = 0;
	if (indent === undefined) indent = "";
	let skipLongHexOctets = flags.ommit_long_octet;

	if (hex.substr(idx, 2) == "01") {
		let v = getV(hex, idx);
		if (v == "00") {
			return indent + "BOOLEAN FALSE\n";
		} else {
			return indent + "BOOLEAN TRUE\n";
		}
	}
	if (hex.substr(idx, 2) == "02") {
		let v = getV(hex, idx);
		return indent + "INTEGER " + skipLongHex(v, skipLongHexOctets) + "\n";
	}
	if (hex.substr(idx, 2) == "03") {
		let v = getV(hex, idx);
		return indent + "BITSTRING " + skipLongHex(v, skipLongHexOctets) + "\n";
	}
	if (hex.substr(idx, 2) == "04") {
		let v = getV(hex, idx);
		if (isASN1HEX(v)) {
			let s = indent + "OCTETSTRING, encapsulates\n";
			s = s + dump(v, flags, 0, indent + "  ");
			return s;
		} else {
			return indent + "OCTETSTRING " + skipLongHex(v, skipLongHexOctets) + "\n";
		}
	}
	if (hex.substr(idx, 2) == "05") {
		return indent + "NULL\n";
	}
	if (hex.substr(idx, 2) == "06") {
		let hV = getV(hex, idx);
		let oidDot = oidHexToInt(hV);
		let oidName = oid2name(oidDot);
		let oidSpc = oidDot.replace(/\./g, ' ');
		if (oidName != '') {
			return indent + "ObjectIdentifier " + oidName + " (" + oidSpc + ")\n";
		} else {
			return indent + "ObjectIdentifier (" + oidSpc + ")\n";
		}
	}
	if (hex.substr(idx, 2) == "0c") {
		return indent + "UTF8String '" + hextoutf8(getV(hex, idx)) + "'\n";
	}
	if (hex.substr(idx, 2) == "13") {
		return indent + "PrintableString '" + hextoutf8(getV(hex, idx)) + "'\n";
	}
	if (hex.substr(idx, 2) == "14") {
		return indent + "TeletexString '" + hextoutf8(getV(hex, idx)) + "'\n";
	}
	if (hex.substr(idx, 2) == "16") {
		return indent + "IA5String '" + hextoutf8(getV(hex, idx)) + "'\n";
	}
	if (hex.substr(idx, 2) == "17") {
		return indent + "UTCTime " + hextoutf8(getV(hex, idx)) + "\n";
	}
	if (hex.substr(idx, 2) == "18") {
		return indent + "GeneralizedTime " + hextoutf8(getV(hex, idx)) + "\n";
	}
	if (hex.substr(idx, 2) == "30") {
		if (hex.substr(idx, 4) == "3000") {
			return indent + "SEQUENCE {}\n";
		}

		let s = indent + "SEQUENCE\n";
		let aIdx = getChildIdx(hex, idx);

		/** @type {Object} */ let flagsTemp = flags;

		if ((aIdx.length == 2 || aIdx.length == 3) &&
			hex.substr(aIdx[0], 2) == "06" &&
			hex.substr(aIdx[aIdx.length - 1], 2) == "04") { // supposed X.509v3 extension
			let oidName = oidname(getV(hex, aIdx[0]));
			let flagsClone = /** @type {Object} */ ( JSON.parse(JSON.stringify(flags)) );
			flagsClone.x509ExtName = oidName;
			flagsTemp = flagsClone;
		}

		for (let i = 0; i < aIdx.length; i++) {
			s = s + dump(hex, flagsTemp, aIdx[i], indent + "  ");
		}
		return s;
	}
	if (hex.substr(idx, 2) == "31") {
		let s = indent + "SET\n";
		let aIdx = getChildIdx(hex, idx);
		for (let i = 0; i < aIdx.length; i++) {
			s = s + dump(hex, flags, aIdx[i], indent + "  ");
		}
		return s;
	}
	let tag = parseInt(hex.substr(idx, 2), 16);
	if ((tag & 128) != 0) { // context specific 
		let tagNumber = tag & 31;
		if ((tag & 32) != 0) { // structured tag
			let s = indent + "[" + tagNumber + "]\n";
			let aIdx = getChildIdx(hex, idx);
			for (let i = 0; i < aIdx.length; i++) {
				s = s + dump(hex, flags, aIdx[i], indent + "  ");
			}
			return s;
		} else { // primitive tag
			let v = getV(hex, idx);
			if (v.substr(0, 8) == "68747470") { // http
				v = hextoutf8(v);
			}
			if (flags.x509ExtName === "subjectAltName" &&
				tagNumber == 2) {
				v = hextoutf8(v);
			}

			let s = indent + "[" + tagNumber + "] " + v + "\n";
			return s;
		}
	}
	return indent + "UNKNOWN(" + hex.substr(idx, 2) + ") " +
		getV(hex, idx) + "\n";
}

/**
 * check wheather the string is ASN.1 hexadecimal string or not
 * @param {string} hex string to check whether it is hexadecmal string for ASN.1 DER or not
 * @return {boolean} true if it is hexadecimal string of ASN.1 data otherwise false
 * @description
 * This method checks wheather the argument 'hex' is a hexadecimal string of
 * ASN.1 data or not.
 * @example
 * isASN1HEX('0203012345') &rarr; true // PROPER ASN.1 INTEGER
 * isASN1HEX('0203012345ff') &rarr; false // TOO LONG VALUE
 * isASN1HEX('02030123') &rarr; false // TOO SHORT VALUE
 * isASN1HEX('fa3bcd') &rarr; false // WRONG FOR ASN.1
 */
export function isASN1HEX(hex) {
	if (hex.length % 2 == 1) return false;

	let intL = getVblen(hex, 0);
	let tV = hex.substr(0, 2);
	let lV = getL(hex, 0);
	let hVLength = hex.length - tV.length - lV.length;
	if (hVLength == intL * 2) return true;

	return false;
}

/**
 * get hexacedimal string from PEM format data<br/>
 * @param {string} oidDotOrHex number dot notation(i.e. 1.2.3) or hexadecimal string for OID
 * @return {string} name for OID
 * @description
 * This static method gets a OID name for
 * a specified string of number dot notation (i.e. 1.2.3) or
 * hexadecimal string.
 * @example
 * oidname("2.5.29.37") &rarr; extKeyUsage
 * oidname("551d25") &rarr; extKeyUsage
 * oidname("0.1.2.3") &rarr; 0.1.2.3 // unknown
 */
export function oidname(oidDotOrHex) {
	if (isHex(oidDotOrHex))
		oidDotOrHex = oidHexToInt(oidDotOrHex);
	let name = oid2name(oidDotOrHex);
	if (name === "") name = oidDotOrHex;
	return name;
}
