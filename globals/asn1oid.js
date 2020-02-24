/*
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

import { DERObjectIdentifier } from "./asn1-1.0.js"

export const oidhex2name = {
	'2a864886f70d010101': 'rsaEncryption',
	'2a8648ce3d0201': 'ecPublicKey',
	'2a8648ce380401': 'dsa',
	'2a8648ce3d030107': 'secp256r1',
	'2b8104001f': 'secp192k1',
	'2b81040021': 'secp224r1',
	'2b8104000a': 'secp256k1',
	'2b81040023': 'secp521r1',
	'2b81040022': 'secp384r1',
	'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
	'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
	'608648016503040302': 'SHA256withDSA', // 2.16.840.1.101.3.4.3.2
};

/**
 * Short attribute type name and oid (ex. 'C' and '2.5.4.6')
 * @type {Object<string, string>}
 */
const atype2oidList = {
	// RFC 4514 AttributeType name string (MUST recognized)
	'CN': '2.5.4.3',
	'L': '2.5.4.7',
	'ST': '2.5.4.8',
	'O': '2.5.4.10',
	'OU': '2.5.4.11',
	'C': '2.5.4.6',
	'STREET': '2.5.4.9',
	'DC': '0.9.2342.19200300.100.1.25',
	'UID': '0.9.2342.19200300.100.1.1',
	// other AttributeType name string
	// http://blog.livedoor.jp/k_urushima/archives/656114.html
	'SN': '2.5.4.4', // surname
	'T': '2.5.4.12', // title
	'DN': '2.5.4.49', // distinguishedName
	'E': '1.2.840.113549.1.9.1', // emailAddress in MS.NET or Bouncy
	// other AttributeType name string (no short name)
	'description': '2.5.4.13',
	'businessCategory': '2.5.4.15',
	'postalCode': '2.5.4.17',
	'serialNumber': '2.5.4.5',
	'uniqueIdentifier': '2.5.4.45',
	'organizationIdentifier': '2.5.4.97',
	'jurisdictionOfIncorporationL': '1.3.6.1.4.1.311.60.2.1.1',
	'jurisdictionOfIncorporationSP': '1.3.6.1.4.1.311.60.2.1.2',
	'jurisdictionOfIncorporationC': '1.3.6.1.4.1.311.60.2.1.3'
};

/**
 * Oid name and oid (ex. 'keyUsage' and '2.5.29.15')
 * @type {Object<string, string>}
 */
const name2oidList = {
	'sha1': '1.3.14.3.2.26',
	'sha256': '2.16.840.1.101.3.4.2.1',
	'sha384': '2.16.840.1.101.3.4.2.2',
	'sha512': '2.16.840.1.101.3.4.2.3',
	'sha224': '2.16.840.1.101.3.4.2.4',
	'md5': '1.2.840.113549.2.5',
	'md2': '1.3.14.7.2.2.1',
	'ripemd160': '1.3.36.3.2.1',

	'MD2withRSA': '1.2.840.113549.1.1.2',
	'MD4withRSA': '1.2.840.113549.1.1.3',
	'MD5withRSA': '1.2.840.113549.1.1.4',
	'SHA1withRSA': '1.2.840.113549.1.1.5',
	'SHA224withRSA': '1.2.840.113549.1.1.14',
	'SHA256withRSA': '1.2.840.113549.1.1.11',
	'SHA384withRSA': '1.2.840.113549.1.1.12',
	'SHA512withRSA': '1.2.840.113549.1.1.13',

	'SHA1withECDSA': '1.2.840.10045.4.1',
	'SHA224withECDSA': '1.2.840.10045.4.3.1',
	'SHA256withECDSA': '1.2.840.10045.4.3.2',
	'SHA384withECDSA': '1.2.840.10045.4.3.3',
	'SHA512withECDSA': '1.2.840.10045.4.3.4',

	'dsa': '1.2.840.10040.4.1',
	'SHA1withDSA': '1.2.840.10040.4.3',
	'SHA224withDSA': '2.16.840.1.101.3.4.3.1',
	'SHA256withDSA': '2.16.840.1.101.3.4.3.2',

	'rsaEncryption': '1.2.840.113549.1.1.1',

	// X.500 AttributeType defined in RFC 4514
	'commonName': '2.5.4.3',
	'countryName': '2.5.4.6',
	'localityName': '2.5.4.7',
	'stateOrProvinceName': '2.5.4.8',
	'streetAddress': '2.5.4.9',
	'organizationName': '2.5.4.10',
	'organizationalUnitName': '2.5.4.11',
	'domainComponent': '0.9.2342.19200300.100.1.25',
	'userId': '0.9.2342.19200300.100.1.1',
	// other AttributeType name string
	'surname': '2.5.4.4',
	'title': '2.5.4.12',
	'distinguishedName': '2.5.4.49',
	'emailAddress': '1.2.840.113549.1.9.1',
	// other AttributeType name string (no short name)
	'description': '2.5.4.13',
	'businessCategory': '2.5.4.15',
	'postalCode': '2.5.4.17',
	'uniqueIdentifier': '2.5.4.45',
	'organizationIdentifier': '2.5.4.97',
	'jurisdictionOfIncorporationL': '1.3.6.1.4.1.311.60.2.1.1',
	'jurisdictionOfIncorporationSP': '1.3.6.1.4.1.311.60.2.1.2',
	'jurisdictionOfIncorporationC': '1.3.6.1.4.1.311.60.2.1.3',

	'subjectKeyIdentifier': '2.5.29.14',
	'keyUsage': '2.5.29.15',
	'subjectAltName': '2.5.29.17',
	'issuerAltName': '2.5.29.18',
	'basicConstraints': '2.5.29.19',
	'nameConstraints': '2.5.29.30',
	'cRLDistributionPoints': '2.5.29.31',
	'certificatePolicies': '2.5.29.32',
	'authorityKeyIdentifier': '2.5.29.35',
	'policyConstraints': '2.5.29.36',
	'extKeyUsage': '2.5.29.37',
	'authorityInfoAccess': '1.3.6.1.5.5.7.1.1',
	'ocsp': '1.3.6.1.5.5.7.48.1',
	'caIssuers': '1.3.6.1.5.5.7.48.2',

	'anyExtendedKeyUsage': '2.5.29.37.0',
	'serverAuth': '1.3.6.1.5.5.7.3.1',
	'clientAuth': '1.3.6.1.5.5.7.3.2',
	'codeSigning': '1.3.6.1.5.5.7.3.3',
	'emailProtection': '1.3.6.1.5.5.7.3.4',
	'timeStamping': '1.3.6.1.5.5.7.3.8',
	'ocspSigning': '1.3.6.1.5.5.7.3.9',

	'ecPublicKey': '1.2.840.10045.2.1',
	'secp256r1': '1.2.840.10045.3.1.7',
	'secp256k1': '1.3.132.0.10',
	'secp384r1': '1.3.132.0.34',

	'pkcs5PBES2': '1.2.840.113549.1.5.13',
	'pkcs5PBKDF2': '1.2.840.113549.1.5.12',

	'des-EDE3-CBC': '1.2.840.113549.3.7',

	'data': '1.2.840.113549.1.7.1', // CMS data
	'signed-data': '1.2.840.113549.1.7.2', // CMS signed-data
	'enveloped-data': '1.2.840.113549.1.7.3', // CMS enveloped-data
	'digested-data': '1.2.840.113549.1.7.5', // CMS digested-data
	'encrypted-data': '1.2.840.113549.1.7.6', // CMS encrypted-data
	'authenticated-data': '1.2.840.113549.1.9.16.1.2', // CMS authenticated-data
	'tstinfo': '1.2.840.113549.1.9.16.1.4', // RFC3161 TSTInfo
	'extensionRequest': '1.2.840.113549.1.9.14',// CSR extensionRequest
};

/**
 * Caching name and DERObjectIdentifier object
 * @type {Object<string, DERObjectIdentifier>}
 */
let objCache = {};

/**
 * get DERObjectIdentifier by registered OID name
 * @param {string} name OID
 * @description
 * @example
 * let asn1ObjOID = name2obj('SHA1withRSA');
 */
export function name2obj(name) {
	if (typeof objCache[name] != "undefined")
		return objCache[name];
	if (typeof name2oidList[name] == "undefined")
		throw "Name of ObjectIdentifier not defined: " + name;
	let oid = name2oidList[name];
	let obj = new DERObjectIdentifier({ 'oid': oid });
	objCache[name] = obj;
	return obj;
}

/**
 * get DERObjectIdentifier by registered attribute type name such like 'C' or 'CN'<br/>
 * @param {string} atype short attribute type name such like 'C' or 'CN'
 * @description
 * @example
 * atype2obj('CN') &rarr; 2.5.4.3
 * atype2obj('OU') &rarr; 2.5.4.11
 */
export function atype2obj(atype) {
	if (typeof objCache[atype] != "undefined")
		return objCache[atype];
	if (typeof atype2oidList[atype] == "undefined")
		throw "AttributeType name undefined: " + atype;
	let oid = atype2oidList[atype];
	let obj = new DERObjectIdentifier({ 'oid': oid });
	objCache[atype] = obj;
	return obj;
}

/**
 * convert OID to name<br/>
 * @param {string} oid dot noted Object Identifer string (ex. 1.2.3.4)
 * @return {string} OID name if registered otherwise empty string
 * @description
 * This static method converts OID string to its name.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * oid2name("1.3.6.1.5.5.7.1.1") &rarr; 'authorityInfoAccess'
 */
export function oid2name(oid) {
	let list = name2oidList;
	for (let name in list) {
		if (list[name] == oid) return name;
	}
	return '';
}

/**
 * convert OID to AttributeType name<br/>
 * @param {string} oid dot noted Object Identifer string (ex. 1.2.3.4)
 * @return {string} OID AttributeType name if registered otherwise oid
 * @description
 * This static method converts OID string to its AttributeType name.
 * If OID is not defined in OID.atype2oidList associative array then it returns OID
 * specified as argument.
 * @example
 * oid2atype("2.5.4.3") &rarr; CN
 * oid2atype("1.3.6.1.4.1.311.60.2.1.3") &rarr; jurisdictionOfIncorporationC
 * oid2atype("0.1.2.3.4") &rarr; 0.1.2.3.4 // unregistered OID
 */
export function oid2atype(oid) {
	let list = atype2oidList;
	for (let atype in list) {
		if (list[atype] == oid) return atype;
	}
	return oid;
}

/**
 * convert OID name to OID value<br/>
 * @param {string} name OID name
 * @return {string} dot noted Object Identifer string (ex. 1.2.3.4)
 * @description
 * This static method converts from OID name to OID string.
 * If OID is undefined then it returns empty string (i.e. '').
 * @example
 * name2oid("authorityInfoAccess") &rarr; 1.3.6.1.5.5.7.1.1
 */
export function name2oid(name) {
	let list = name2oidList;
	if (list[name] === undefined) return '';
	return list[name];
}
