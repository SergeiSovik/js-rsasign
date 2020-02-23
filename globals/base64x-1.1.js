/*
 * base64x.js - Base64url and supplementary functions for Tom Wu's base64.js library
 *
 * version: 1.1.14 (2018-Apr-21)
 *
 * Original work Copyright (c) 2012-2018 Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergio Rando <sergio.rando@yahoo.com>
 *
 * This software is licensed under the terms of the MIT License.
 * https://kjur.github.io/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

"use strict";

import { hex2b64, b64toBA, b64tohex } from "./../../js-bn/modules/base64.js"

/**
 * <br/>
 * This module provides static methods for string utility.
 * <dl>
 * <dt><b>STRING TYPE CHECKERS</b>
 * <dd>
 * <ul>
 * <li>{@link isInteger} - check whether argument is an integer</li>
 * <li>{@link isHex} - check whether argument is a hexadecimal string</li>
 * <li>{@link isBase64} - check whether argument is a Base64 encoded string</li>
 * <li>{@link isBase64URL} - check whether argument is a Base64URL encoded string</li>
 * <li>{@link isIntegerArray} - check whether argument is an array of integers</li>
 * </ul>
 * </dl>
 */

/**
 * convert a string to an array of character codes
 * @param {string} s
 * @return {Array<number>} 
 */
export function stoBA(s) {
	/** @type {Array<number>} */ let a = new Array();
	for (let i = 0; i < s.length; i++) {
		a[i] = s.charCodeAt(i);
	}
	return a;
}

/**
 * convert an array of character codes to a string
 * @param {Array<number>} a array of character codes
 * @return {string} s
 */
export function BAtos(a) {
	let s = "";
	for (let i = 0; i < a.length; i++) {
		s = s + String.fromCharCode(a[i]);
	}
	return s;
}

/**
 * convert an array of bytes(Number) to hexadecimal string.<br/>
 * @param {Array<number>} a array of bytes
 * @return {string} hexadecimal string
 */
export function BAtohex(a) {
	let s = "";
	for (let i = 0; i < a.length; i++) {
		let hex1 = a[i].toString(16);
		if (hex1.length == 1) hex1 = "0" + hex1;
		s = s + hex1;
	}
	return s;
}

/**
 * convert a ASCII string to a hexadecimal string of ASCII codes.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {string} s ASCII string
 * @return {string} hexadecimal string
 */
export function stohex(s) {
	return BAtohex(stoBA(s));
}

/**
 * convert a ASCII string to a Base64 encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {string} s ASCII string
 * @return {string} Base64 encoded string
 */
export function stob64(s) {
	return hex2b64(stohex(s));
}

/**
 * convert a ASCII string to a Base64URL encoded string.<br/>
 * NOTE: This can't be used for non ASCII characters.
 * @param {string} s ASCII string
 * @return {string} Base64URL encoded string
 */
export function stob64u(s) {
	return b64tob64u(hex2b64(stohex(s)));
}

/**
 * convert a Base64URL encoded string to a ASCII string.<br/>
 * NOTE: This can't be used for Base64URL encoded non ASCII characters.
 * @param {string} s Base64URL encoded string
 * @return {string} ASCII string
 */
export function b64utos(s) {
	return BAtos(b64toBA(b64utob64(s)));
}

/**
 * convert a Base64 encoded string to a Base64URL encoded string.<br/>
 * @param {string} s Base64 encoded string
 * @return {string} Base64URL encoded string
 * @example
 * b64tob64u("ab+c3f/==") &rarr; "ab-c3f_"
 */
export function b64tob64u(s) {
	s = s.replace(/\=/g, "");
	s = s.replace(/\+/g, "-");
	s = s.replace(/\//g, "_");
	return s;
}

/**
 * convert a Base64URL encoded string to a Base64 encoded string.<br/>
 * @param {string} s Base64URL encoded string
 * @return {string} Base64 encoded string
 * @example
 * b64utob64("ab-c3f_") &rarr; "ab+c3f/=="
 */
export function b64utob64(s) {
	if (s.length % 4 == 2) s = s + "==";
	else if (s.length % 4 == 3) s = s + "=";
	s = s.replace(/-/g, "+");
	s = s.replace(/_/g, "/");
	return s;
}

/**
 * convert a hexadecimal string to a Base64URL encoded string.<br/>
 * @param {string} s hexadecimal string
 * @return {string} Base64URL encoded string
 * @description
 * convert a hexadecimal string to a Base64URL encoded string.
 * NOTE: If leading "0" is omitted and odd number length for
 * hexadecimal leading "0" is automatically added.
 */
export function hextob64u(s) {
	if (s.length % 2 == 1) s = "0" + s;
	return b64tob64u(hex2b64(s));
}

/**
 * convert a Base64URL encoded string to a hexadecimal string.<br/>
 * @param {string} s Base64URL encoded string
 * @return {string} hexadecimal string
 */
export function b64utohex(s) {
	return b64tohex(b64utob64(s));
}

/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64URL encoded string.<br/>
 * @param {string} s UTF-8 encoded string
 * @return {string} Base64URL encoded string
 */
export let utf8tob64u = (typeof Buffer === 'function') ?
	function (s) {
		return b64tob64u(new Buffer(s, 'utf8').toString('base64'));
	} : function (s) {
		return hextob64u(uricmptohex(encodeURIComponentAll(s)));
	};

/**
 * convert a Base64URL encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @param {string} s Base64URL encoded string
 * @return {string} UTF-8 encoded string
 */
export let b64utoutf8 = (typeof Buffer === 'function') ?
	function (s) {
		return new Buffer(b64utob64(s), 'base64').toString('utf8');
	} : function (s) {
		return decodeURIComponent(hextouricmp(b64utohex(s)));
	};

/**
 * convert a UTF-8 encoded string including CJK or Latin to a Base64 encoded string.<br/>
 * @param {string} s UTF-8 encoded string
 * @return {string} Base64 encoded string
 */
export function utf8tob64(s) {
	return hex2b64(uricmptohex(encodeURIComponentAll(s)));
}

/**
 * convert a Base64 encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * @param {string} s Base64 encoded string
 * @return {string} UTF-8 encoded string
 */
export function b64toutf8(s) {
	return decodeURIComponent(hextouricmp(b64tohex(s)));
}

/**
 * convert a UTF-8 encoded string including CJK or Latin to a hexadecimal encoded string.<br/>
 * @param {string} s UTF-8 encoded string
 * @return {string} hexadecimal encoded string
 */
export function utf8tohex(s) {
	return uricmptohex(encodeURIComponentAll(s));
}

/**
 * convert a hexadecimal encoded string to a UTF-8 encoded string including CJK or Latin.<br/>
 * Note that when input is improper hexadecimal string as UTF-8 string, this function returns
 * 'null'.
 * @param {string} s hexadecimal encoded string
 * @return {string} UTF-8 encoded string or null
 */
export function hextoutf8(s) {
	return decodeURIComponent(hextouricmp(s));
}

/**
 * convert a hexadecimal encoded string to raw string including non printable characters.<br/>
 * @param {string} sHex hexadecimal encoded string
 * @return {string} raw string
 * @example
 * hextorstr("610061") &rarr; "a\x00a"
 */
export function hextorstr(sHex) {
	let s = "";
	for (let i = 0; i < sHex.length - 1; i += 2) {
		s += String.fromCharCode(parseInt(sHex.substr(i, 2), 16));
	}
	return s;
}

/**
 * convert a raw string including non printable characters to hexadecimal encoded string.<br/>
 * @param {string} s raw string
 * @return {string} hexadecimal encoded string
 * @example
 * rstrtohex("a\x00a") &rarr; "610061"
 */
export function rstrtohex(s) {
	let result = "";
	for (let i = 0; i < s.length; i++) {
		result += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
	}
	return result;
}

/**
 * convert a hexadecimal string to Base64 encoded string<br/>
 * @param {string} s hexadecimal string
 * @return {string} resulted Base64 encoded string
 * @description
 * This function converts from a hexadecimal string to Base64 encoded
 * string without new lines.
 * @example
 * hextob64("616161") &rarr; "YWFh"
 */
export function hextob64(s) {
	return hex2b64(s);
}

/**
 * convert a hexadecimal string to Base64 encoded string with new lines<br/>
 * @param {string} s hexadecimal string
 * @return {string} resulted Base64 encoded string with new lines
 * @description
 * This function converts from a hexadecimal string to Base64 encoded
 * string with new lines for each 64 characters. This is useful for
 * PEM encoded file.
 * @example
 * hextob64nl("123456789012345678901234567890123456789012345678901234567890")
 * &rarr;
 * MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4 // new line
 * OTAxMjM0NTY3ODkwCg==
 */
export function hextob64nl(s) {
	let b64 = hextob64(s);
	let b64nl = b64.replace(/(.{64})/g, "$1\r\n");
	b64nl = b64nl.replace(/\r\n$/, '');
	return b64nl;
}

/**
 * convert a Base64 encoded string with new lines to a hexadecimal string<br/>
 * @param {string} s Base64 encoded string with new lines
 * @return {string} hexadecimal string
 * @description
 * This function converts from a Base64 encoded
 * string with new lines to a hexadecimal string.
 * This is useful to handle PEM encoded file.
 * This function removes any non-Base64 characters (i.e. not 0-9,A-Z,a-z,\,+,=)
 * including new line.
 * @example
 * hextob64nl(
 * "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4\r\n" +
 * "OTAxMjM0NTY3ODkwCg==\r\n")
 * &rarr;
 * "123456789012345678901234567890123456789012345678901234567890"
 */
export function b64nltohex(s) {
	let b64 = s.replace(/[^0-9A-Za-z\/+=]*/g, '');
	let hex = b64tohex(b64);
	return hex;
}

/**
 * get PEM string from hexadecimal data and header string
 * @param {string} dataHex hexadecimal string of PEM body
 * @param {string} pemHeader PEM header string (ex. 'RSA PRIVATE KEY')
 * @return {string} PEM formatted string of input data
 * @description
 * This function converts a hexadecimal string to a PEM string with
 * a specified header. Its line break will be CRLF("\r\n").
 * @example
 * hextopem('616161', 'RSA PRIVATE KEY') &rarr;
 * -----BEGIN PRIVATE KEY-----
 * YWFh
 * -----END PRIVATE KEY-----
 */
export function hextopem(dataHex, pemHeader) {
	let pemBody = hextob64nl(dataHex);
	return "-----BEGIN " + pemHeader + "-----\r\n" +
		pemBody +
		"\r\n-----END " + pemHeader + "-----\r\n";
}

/**
 * get hexacedimal string from PEM format data<br/>
 * @param {string} s PEM formatted string
 * @param {string=} sHead PEM header string without BEGIN/END(OPTION)
 * @return {string} hexadecimal string data of PEM contents
 * @description
 * This static method gets a hexacedimal string of contents 
 * from PEM format data. You can explicitly specify PEM header 
 * by sHead argument. 
 * Any space characters such as white space or new line
 * will be omitted.<br/>
 * NOTE: Now {@link KEYUTIL.getHexFromPEM} and {@link X509.pemToHex}
 * have been deprecated since jsrsasign 7.2.1. 
 * Please use this method instead.
 * @example
 * pemtohex("-----BEGIN PUBLIC KEY...") &rarr; "3082..."
 * pemtohex("-----BEGIN CERTIFICATE...", "CERTIFICATE") &rarr; "3082..."
 * pemtohex(" \r\n-----BEGIN DSA PRIVATE KEY...") &rarr; "3082..."
 */
export function pemtohex(s, sHead) {
	if (s.indexOf("-----BEGIN ") == -1)
		throw "can't find PEM header: " + sHead;

	if (sHead !== undefined) {
		s = s.replace("-----BEGIN " + sHead + "-----", "");
		s = s.replace("-----END " + sHead + "-----", "");
	} else {
		s = s.replace(/-----BEGIN [^-]+-----/, '');
		s = s.replace(/-----END [^-]+-----/, '');
	}
	return b64nltohex(s);
}

/**
 * convert a hexadecimal string to an ArrayBuffer<br/>
 * @param {string} hex hexadecimal string
 * @return {ArrayBuffer} ArrayBuffer
 * @description
 * This function converts from a hexadecimal string to an ArrayBuffer.
 * @example
 * hextoArrayBuffer("fffa01") &rarr; ArrayBuffer of [255, 250, 1]
 */
export function hextoArrayBuffer(hex) {
	if (hex.length % 2 != 0) throw "input is not even length";
	if (hex.match(/^[0-9A-Fa-f]+$/) == null) throw "input is not hexadecimal";

	let buffer = new ArrayBuffer(hex.length / 2);
	let view = new DataView(buffer);

	for (let i = 0; i < hex.length / 2; i++) {
		view.setUint8(i, parseInt(hex.substr(i * 2, 2), 16));
	}

	return buffer;
}

/**
 * convert an ArrayBuffer to a hexadecimal string<br/>
 * @param {ArrayBuffer} buffer ArrayBuffer
 * @return {string} hexadecimal string
 * @description
 * This function converts from an ArrayBuffer to a hexadecimal string.
 * @example
 * let buffer = new ArrayBuffer(3);
 * let view = new DataView(buffer);
 * view.setUint8(0, 0xfa);
 * view.setUint8(1, 0xfb);
 * view.setUint8(2, 0x01);
 * ArrayBuffertohex(buffer) &rarr; "fafb01"
 */
export function ArrayBuffertohex(buffer) {
	let hex = "";
	let view = new DataView(buffer);

	for (let i = 0; i < buffer.byteLength; i++) {
		hex += ("00" + view.getUint8(i).toString(16)).slice(-2);
	}

	return hex;
}

/**
 * GeneralizedTime or UTCTime string to milliseconds from Unix origin<br>
 * @param {string} s GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @return {number} milliseconds from Unix origin time (i.e. Jan 1, 1970 0:00:00 UTC)
 * @description
 * This function converts from GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ) to milliseconds from Unix origin time
 * (i.e. Jan 1 1970 0:00:00 UTC). 
 * Argument string may have fraction of seconds and
 * its length is one or more digits such as "20170410235959.1234567Z".
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * @example
 * zulutomsec(  "071231235959Z")       &rarr; 1199145599000 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec(  "071231235959.1Z")     &rarr; 1199145599100 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec(  "071231235959.12345Z") &rarr; 1199145599123 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec("20071231235959Z")       &rarr; 1199145599000 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutomsec(  "931231235959Z")       &rarr; -410227201000 #Mon, 31 Dec 1956 23:59:59 GMT
 */
export function zulutomsec(s) {
	let year, month, day, hour, min, sec, msec, d;
	let sYear, sFrac, sMsec, matchResult;

	matchResult = s.match(/^(\d{2}|\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(|\.\d+)Z$/);

	if (matchResult) {
		sYear = matchResult[1];
		year = parseInt(sYear, 10);
		if (sYear.length === 2) {
			if (50 <= year && year < 100) {
				year = 1900 + year;
			} else if (0 <= year && year < 50) {
				year = 2000 + year;
			}
		}
		month = parseInt(matchResult[2], 10) - 1;
		day = parseInt(matchResult[3], 10);
		hour = parseInt(matchResult[4], 10);
		min = parseInt(matchResult[5], 10);
		sec = parseInt(matchResult[6], 10);
		msec = 0;

		sFrac = matchResult[7];
		if (sFrac !== "") {
			sMsec = (sFrac.substr(1) + "00").substr(0, 3); // .12 -> 012
			msec = parseInt(sMsec, 10);
		}
		return Date.UTC(year, month, day, hour, min, sec, msec);
	}
	throw "unsupported zulu format: " + s;
}

/**
 * GeneralizedTime or UTCTime string to seconds from Unix origin<br>
 * @param {string} s GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @return {number} seconds from Unix origin time (i.e. Jan 1, 1970 0:00:00 UTC)
 * @description
 * This function converts from GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ) to seconds from Unix origin time
 * (i.e. Jan 1 1970 0:00:00 UTC). Argument string may have fraction of seconds 
 * however result value will be omitted.
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * @example
 * zulutosec(  "071231235959Z")       &rarr; 1199145599 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutosec(  "071231235959.1Z")     &rarr; 1199145599 #Mon, 31 Dec 2007 23:59:59 GMT
 * zulutosec("20071231235959Z")       &rarr; 1199145599 #Mon, 31 Dec 2007 23:59:59 GMT
 */
export function zulutosec(s) {
	let msec = zulutomsec(s);
	return ~~(msec / 1000);
}

/**
 * GeneralizedTime or UTCTime string to Date object<br>
 * @param {string} s GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @return {Date} Date object for specified time
 * @description
 * This function converts from GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ) to Date object.
 * Argument string may have fraction of seconds and
 * its length is one or more digits such as "20170410235959.1234567Z".
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * @example
 * zulutodate(  "071231235959Z").toUTCString()   &rarr; "Mon, 31 Dec 2007 23:59:59 GMT"
 * zulutodate(  "071231235959.1Z").toUTCString() &rarr; "Mon, 31 Dec 2007 23:59:59 GMT"
 * zulutodate("20071231235959Z").toUTCString()   &rarr; "Mon, 31 Dec 2007 23:59:59 GMT"
 * zulutodate(  "071231235959.34").getMilliseconds() &rarr; 340
 */
export function zulutodate(s) {
	return new Date(zulutomsec(s));
}

/**
 * Date object to zulu time string<br>
 * @param {Date} d Date object for specified time
 * @param {boolean} flagUTCTime if this is true year will be YY otherwise YYYY
 * @param {boolean} flagMilli if this is true result concludes milliseconds
 * @return {string} GeneralizedTime or UTCTime string (ex. 20170412235959.384Z)
 * @description
 * This function converts from Date object to GeneralizedTime string (i.e. YYYYMMDDHHmmSSZ) or
 * UTCTime string (i.e. YYMMDDHHmmSSZ).
 * As for UTCTime, if year "YY" is equal or less than 49 then it is 20YY.
 * If year "YY" is equal or greater than 50 then it is 19YY.
 * If flagMilli is true its result concludes milliseconds such like
 * "20170520235959.42Z". 
 * @example
 * d = new Date(Date.UTC(2017,4,20,23,59,59,670));
 * datetozulu(d) &rarr; "20170520235959Z"
 * datetozulu(d, true) &rarr; "170520235959Z"
 * datetozulu(d, false, true) &rarr; "20170520235959.67Z"
 */
export function datetozulu(d, flagUTCTime, flagMilli) {
	let s;
	let year = d.getUTCFullYear();
	if (flagUTCTime) {
		if (year < 1950 || 2049 < year)
			throw "not proper year for UTCTime: " + year;
		s = ("" + year).slice(-2);
	} else {
		s = ("000" + year).slice(-4);
	}
	s += ("0" + (d.getUTCMonth() + 1)).slice(-2);
	s += ("0" + d.getUTCDate()).slice(-2);
	s += ("0" + d.getUTCHours()).slice(-2);
	s += ("0" + d.getUTCMinutes()).slice(-2);
	s += ("0" + d.getUTCSeconds()).slice(-2);
	if (flagMilli) {
		let milli = d.getUTCMilliseconds();
		if (milli !== 0) {
			milli = ("00" + milli).slice(-3);
			milli = milli.replace(/0+$/g, "");
			s += "." + milli;
		}
	}
	s += "Z";
	return s;
}

/**
 * convert a URLComponent string such like "%67%68" to a hexadecimal string.<br/>
 * @param {string} s URIComponent string such like "%67%68"
 * @return {string} hexadecimal string
 */
export function uricmptohex(s) {
	return s.replace(/%/g, "");
}

/**
 * convert a hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * @param {string} s hexadecimal string
 * @return {string} URIComponent string such like "%67%68"
 */
export function hextouricmp(s) {
	return s.replace(/(..)/g, "%$1");
}

/**
 * convert any IPv6 address to a 16 byte hexadecimal string
 * @param s string of IPv6 address
 * @return {string} 16 byte hexadecimal string of IPv6 address
 * @description
 * This function converts any IPv6 address representation string
 * to a 16 byte hexadecimal string of address.
 */
export function ipv6tohex(s) {
	let msgMalformedAddress = "malformed IPv6 address";
	if (!s.match(/^[0-9A-Fa-f:]+$/))
		throw msgMalformedAddress;

	// 1. downcase
	s = s.toLowerCase();

	// 2. expand ::
	let num_colon = s.split(':').length - 1;
	if (num_colon < 2) throw msgMalformedAddress;
	let colon_replacer = ':'.repeat(7 - num_colon + 2);
	s = s.replace('::', colon_replacer);

	// 3. fill zero
	let a = s.split(':');
	if (a.length != 8) throw msgMalformedAddress;
	for (let i = 0; i < 8; i++) {
		a[i] = ("0000" + a[i]).slice(-4);
	}
	return a.join('');
}

/**
 * convert a 16 byte hexadecimal string to RFC 5952 canonicalized IPv6 address<br/>
 * @param {string} s hexadecimal string of 16 byte IPv6 address
 * @return {string} IPv6 address string canonicalized by RFC 5952
 * @description
 * This function converts a 16 byte hexadecimal string to 
 * <a href="https://tools.ietf.org/html/rfc5952">RFC 5952</a>
 * canonicalized IPv6 address string.
 * @example
 * hextoip("871020010db8000000000000000000000004") &rarr "2001:db8::4"
 * hextoip("871020010db8000000000000000000") &rarr raise exception
 * hextoip("xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz") &rarr raise exception
 */
export function hextoipv6(s) {
	if (!s.match(/^[0-9A-Fa-f]{32}$/))
		throw "malformed IPv6 address octet";

	// 1. downcase
	s = s.toLowerCase();

	// 2. split 4
	let a = s.match(/.{1,4}/g);

	// 3. trim leading 0
	for (let i = 0; i < 8; i++) {
		a[i] = a[i].replace(/^0+/, "");
		if (a[i] == '') a[i] = '0';
	}
	s = ":" + a.join(":") + ":";

	// 4. find shrinkables :0:0:...
	let aZero = s.match(/:(0:){2,}/g);

	// 5. no shrinkable
	if (aZero === null) return s.slice(1, -1);

	// 6. find max length :0:0:...
	let item = '';
	for (let i = 0; i < aZero.length; i++) {
		if (aZero[i].length > item.length) item = aZero[i];
	}

	// 7. shrink
	s = s.replace(item, '::');
	return s.slice(1, -1);
}

/**
 * convert a hexadecimal string to IP addresss<br/>
 * @param {string} s hexadecimal string of IP address
 * @return {string} IP address string
 * @description
 * This function converts a hexadecimal string of IPv4 or 
 * IPv6 address to IPv4 or IPv6 address string.
 * If byte length is not 4 nor 16, this returns a
 * hexadecimal string without conversion.
 * @example
 * hextoip("c0a80101") &rarr "192.168.1.1"
 * hextoip("871020010db8000000000000000000000004") &rarr "2001:db8::4"
 * hextoip("c0a801010203") &rarr "c0a801010203" // 6 bytes
 * hextoip("zzz")) &rarr raise exception because of not hexadecimal
 */
export function hextoip(s) {
	let malformedMsg = "malformed hex value";
	if (!s.match(/^([0-9A-Fa-f][0-9A-Fa-f]){1,}$/))
		throw malformedMsg;
	if (s.length == 8) { // ipv4
		let ip;
		try {
			ip = parseInt(s.substr(0, 2), 16) + "." +
				parseInt(s.substr(2, 2), 16) + "." +
				parseInt(s.substr(4, 2), 16) + "." +
				parseInt(s.substr(6, 2), 16);
			return ip;
		} catch (ex) {
			throw malformedMsg;
		}
	} else if (s.length == 32) {
		return hextoipv6(s);
	} else {
		return s;
	}
}

/**
 * convert IPv4/v6 addresss to a hexadecimal string<br/>
 * @param {string} s IPv4/v6 address string
 * @return {string} hexadecimal string of IP address
 * @description
 * This function converts IPv4 or IPv6 address string to
 * a hexadecimal string of IPv4 or IPv6 address.
 * @example
 * iptohex("192.168.1.1") &rarr "c0a80101"
 * iptohex("2001:db8::4") &rarr "871020010db8000000000000000000000004"
 * iptohex("zzz")) &rarr raise exception
 */
export function iptohex(s) {
	let malformedMsg = "malformed IP address";
	s = s.toLowerCase();

	if (s.match(/^[0-9.]+$/)) {
		let a = s.split(".");
		if (a.length !== 4) throw malformedMsg;
		let hex = "";
		try {
			for (let i = 0; i < 4; i++) {
				let d = parseInt(a[i], 10);
				hex += ("0" + d.toString(16)).slice(-2);
			}
			return hex;
		} catch (ex) {
			throw malformedMsg;
		}
	} else if (s.match(/^[0-9a-f:]+$/) && s.indexOf(":") !== -1) {
		return ipv6tohex(s);
	} else {
		throw malformedMsg;
	}
}

/**
 * convert UTFa hexadecimal string to a URLComponent string such like "%67%68".<br/>
 * Note that these "<code>0-9A-Za-z!'()*-._~</code>" characters will not
 * converted to "%xx" format by builtin 'encodeURIComponent()' function.
 * However this 'encodeURIComponentAll()' function will convert 
 * all of characters into "%xx" format.
 * @param {string} u8 hexadecimal string
 * @return {string} URIComponent string such like "%67%68"
 */
export function encodeURIComponentAll(u8) {
	let s = encodeURIComponent(u8);
	let s2 = "";
	for (let i = 0; i < s.length; i++) {
		if (s[i] == "%") {
			s2 = s2 + s.substr(i, 3);
			i = i + 2;
		} else {
			s2 = s2 + "%" + stohex(s[i]);
		}
	}
	return s2;
}

/**
 * convert all DOS new line("\r\n") to UNIX new line("\n") in 
 * a String "s".
 * @param {string} s string 
 * @return {string} converted string
 */
export function newline_toUnix(s) {
	s = s.replace(/\r\n/mg, "\n");
	return s;
}

/**
 * convert all UNIX new line("\r\n") to DOS new line("\n") in 
 * a String "s".
 * @param {string} s string 
 * @return {string} converted string
 */
export function newline_toDos(s) {
	s = s.replace(/\r\n/mg, "\n");
	s = s.replace(/\n/mg, "\r\n");
	return s;
}

/**
 * check whether a string is an integer string or not<br/>
 * @param {string} s input string
 * @return {boolean} true if a string "s" is an integer string otherwise false
 * @example
 * isInteger("12345") &rarr; true
 * isInteger("123ab") &rarr; false
 */
export function isInteger(s) {
	if (s.match(/^[0-9]+$/)) {
		return true;
	} else if (s.match(/^-[0-9]+$/)) {
		return true;
	} else {
		return false;
	}
}

/**
 * check whether a string is an hexadecimal string or not<br/>
 * @param {string} s input string
 * @return {boolean} true if a string "s" is an hexadecimal string otherwise false
 * @example
 * isHex("1234") &rarr; true
 * isHex("12ab") &rarr; true
 * isHex("12AB") &rarr; true
 * isHex("12ZY") &rarr; false
 * isHex("121") &rarr; false -- odd length
 */
export function isHex(s) {
	if (s.length % 2 == 0 &&
		(s.match(/^[0-9a-f]+$/) || s.match(/^[0-9A-F]+$/))) {
		return true;
	} else {
		return false;
	}
}

/**
 * check whether a string is a base64 encoded string or not<br/>
 * Input string can conclude new lines or space characters.
 * @param {string} s input string
 * @return {boolean} true if a string "s" is a base64 encoded string otherwise false
 * @example
 * isBase64("YWE=") &rarr; true
 * isBase64("YW_=") &rarr; false
 * isBase64("YWE") &rarr; false -- length shall be multiples of 4
 */
export function isBase64(s) {
	s = s.replace(/\s+/g, "");
	if (s.match(/^[0-9A-Za-z+\/]+={0,3}$/) && s.length % 4 == 0) {
		return true;
	} else {
		return false;
	}
}

/**
 * check whether a string is a base64url encoded string or not<br/>
 * Input string can conclude new lines or space characters.
 * @param {string} s input string
 * @return {boolean} true if a string "s" is a base64url encoded string otherwise false
 * @example
 * isBase64URL("YWE") &rarr; true
 * isBase64URL("YW-") &rarr; true
 * isBase64URL("YW+") &rarr; false
 */
export function isBase64URL(s) {
	if (s.match(/[+/=]/)) return false;
	s = b64utob64(s);
	return isBase64(s);
}

/**
 * check whether a string is a string of integer array or not<br/>
 * Input string can conclude new lines or space characters.
 * @param {string} s input string
 * @return {boolean} true if a string "s" is a string of integer array otherwise false
 * @example
 * isIntegerArray("[1,2,3]") &rarr; true
 * isIntegerArray("  [1, 2, 3  ] ") &rarr; true
 * isIntegerArray("[a,2]") &rarr; false
 */
export function isIntegerArray(s) {
	s = s.replace(/\s+/g, "");
	if (s.match(/^\[[0-9,]+\]$/)) {
		return true;
	} else {
		return false;
	}
}

/**
 * canonicalize hexadecimal string of positive integer<br/>
 * @param {string} s hexadecimal string 
 * @return {string} canonicalized hexadecimal string of positive integer
 * @description
 * This method canonicalize a hexadecimal string of positive integer
 * for two's complement representation.
 * Canonicalized hexadecimal string of positive integer will be:
 * <ul>
 * <li>Its length is always even.</li>
 * <li>If odd length it will be padded with leading zero.<li>
 * <li>If it is even length and its first character is "8" or greater,
 * it will be padded with "00" to make it positive integer.</li>
 * </ul>
 * @example
 * hextoposhex("abcd") &rarr; "00abcd"
 * hextoposhex("1234") &rarr; "1234"
 * hextoposhex("12345") &rarr; "012345"
 */
export function hextoposhex(s) {
	if (s.length % 2 == 1) return "0" + s;
	if (s.substr(0, 1) > "7") return "00" + s;
	return s;
}

/**
 * convert string of integer array to hexadecimal string.<br/>
 * @param {string} s string of integer array
 * @return {string} hexadecimal string
 * @throws "malformed integer array string: *" for wrong input
 * @description
 * This function converts a string of JavaScript integer array to
 * a hexadecimal string. Each integer value shall be in a range 
 * from 0 to 255 otherwise it raise exception. Input string can
 * have extra space or newline string so that they will be ignored.
 * 
 * @example
 * intarystrtohex(" [123, 34, 101, 34, 58] ")
 * &rarr; 7b2265223a (i.e. '{"e":' as string)
 */
export function intarystrtohex(s) {
	s = s.replace(/^\s*\[\s*/, '');
	s = s.replace(/\s*\]\s*$/, '');
	s = s.replace(/\s*/g, '');
	try {
		let hex = s.split(/,/).map(function (element, index, array) {
			let i = parseInt(element, 10);
			if (i < 0 || 255 < i) throw "integer not in range 0-255";
			let hI = ("00" + i.toString(16)).slice(-2);
			return hI;
		}).join('');
		return hex;
	} catch (ex) {
		throw "malformed integer array string: " + ex;
	}
}

/**
 * find index of string where two string differs
 * @param {string} s1 string to compare
 * @param {string} s2 string to compare
 * @return {number} string index of where character differs. Return -1 if same.
 * @example
 * strdiffidx("abcdefg", "abcd4fg") -> 4
 * strdiffidx("abcdefg", "abcdefg") -> -1
 * strdiffidx("abcdefg", "abcdef") -> 6
 * strdiffidx("abcdefgh", "abcdef") -> 6
 */
export function strdiffidx(s1, s2) {
	let n = s1.length;
	if (s1.length > s2.length) n = s2.length;
	for (let i = 0; i < n; i++) {
		if (s1.charCodeAt(i) != s2.charCodeAt(i)) return i;
	}
	if (s1.length != s2.length) return n;
	return -1; // same
}
