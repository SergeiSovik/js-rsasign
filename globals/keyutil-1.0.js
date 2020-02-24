/*
 * keyutil.js - key utility for PKCS#1/5/8 PEM, RSA/DSA/ECDSA key object
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

import { DERInteger, DERObjectIdentifier, newObject, ASN1Object } from "./asn1-1.0.js"
import { SubjectPublicKeyInfo } from "./asn1x509-1.0.js"
import { Hex } from "./../../js-crypto/modules/enc-hex.js"
import { CipherHelper } from "./../../js-crypto/modules/cipher-core.js"
import { CipherParams } from "./../../js-crypto/modules/cipher-params.js"
import { Base64 } from "./../../js-crypto/modules/enc-base64.js"
import { AES } from "./../../js-crypto/modules/aes.js"
import { DES, TripleDES } from "./../../js-crypto/modules/tripledes.js"
import { WordArray } from "./../../js-crypto/modules/wordarray.js"
import { Utf8 } from "./../../js-crypto/modules/enc-utf8.js"
import { HasherMD5 } from "./../../js-crypto/modules/md5.js"
import { getChildIdx, getV, getVidx, getVbyList, getTLV } from "./asn1hex-1.1.js"
import { PBKDF2 } from "./../../js-crypto/modules/pbkdf2.js"
import { DSA } from "./dsa-2.0.js"
import { oidhex2name } from "./asn1oid.js"
import { ECDSA } from "./ecdsa-modified-1.0.js"
import { RSAKeyEx } from "./rsaex.js"
import { getPublicKeyFromCertHex, getPublicKeyFromCertPEM } from "./x509-1.1.js"
import { pemtohex, hextopem, hextob64u, b64utohex } from "./base64x-1.1.js"
import { BigInteger } from "./../../js-bn/modules/jsbn.js"

/** @typedef {RSAKeyEx | DSA | ECDSA} KeyObject */ export var KeyObject

/** * @description 
 * <br/>
 * {@link keyutil-1.0.js} module is an update of former {@link PKCS5PKEY} class.
 * {@link keyutil-1.0.js} module has following features:
 * <dl>
 * <dt><b>key loading - {@link getKey}</b>
 * <dd>
 * <ul>
 * <li>supports RSAKeyEx and ECDSA and DSA key object</li>
 * <li>supports private key and public key</li>
 * <li>supports encrypted and plain private key</li>
 * <li>supports PKCS#1, PKCS#5 and PKCS#8 key</li>
 * <li>supports public key in X.509 certificate</li>
 * <li>key represented by JSON object</li>
 * </ul>
 * NOTE1: Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES <br/>
 * NOTE2: Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC <br/>
 *
 * <dt><b>exporting key - {@link getPEM}</b>
 * <dd>
 * {@link getPEM} method supports following formats:
 * <ul>
 * <li>supports RSA/EC/DSA keys</li>
 * <li>PKCS#1 plain RSA/EC/DSA private key</li>
 * <li>PKCS#5 encrypted RSA/EC/DSA private key with DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>PKCS#8 plain RSA/EC/DSA private key</li>
 * <li>PKCS#8 encrypted RSA/EC/DSA private key with PBKDF2_HmacSHA1_3DES</li>
 * </ul>
 *
 * <dt><b>keypair generation - {@link generateKeypair}</b>
 * <ul>
 * <li>generate key pair of {@link RSAKeyEx} or {@link ECDSA}.</li>
 * <li>generate private key and convert it to PKCS#5 encrypted private key.</li>
 * </ul>
 * NOTE: {@link DSA} is not yet supported.
 * </dl>
 * 
 * @example
 * // 1. loading PEM private key
 * let key = getKey(pemPKCS1PrivateKey);
 * let key = getKey(pemPKCS5EncryptedPrivateKey, "passcode");
 * let key = getKey(pemPKC85PlainPrivateKey);
 * let key = getKey(pemPKC85EncryptedPrivateKey, "passcode");
 * // 2. loading PEM public key
 * let key = getKey(pemPKCS8PublicKey);
 * let key = getKey(pemX509Certificate);
 * // 3. exporting private key
 * let pem = getPEM(privateKeyObj, "PKCS1PRV");
 * let pem = getPEM(privateKeyObj, "PKCS5PRV", "passcode"); // DES-EDE3-CBC by default
 * let pem = getPEM(privateKeyObj, "PKCS5PRV", "passcode", "DES-CBC");
 * let pem = getPEM(privateKeyObj, "PKCS8PRV");
 * let pem = getPEM(privateKeyObj, "PKCS8PRV", "passcode");
 * // 4. exporting public key
 * let pem = getPEM(publicKeyObj);
 */

/**
 * @param {CipherHelper} f 
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function decryptGeneral(f, dataHex, keyHex, ivHex) {
	let data = Hex.parse(dataHex);
	let key = Hex.parse(keyHex);
	let iv = Hex.parse(ivHex);
	let encrypted = new CipherParams({
		'key': key,
		'iv': iv,
		'ciphertext': data
	});
	let decrypted = f.decrypt(encrypted, key, { 'iv': iv });
	return Hex.stringify(decrypted);
}

/**
 * @param {CipherHelper} f 
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function encryptGeneral(f, dataHex, keyHex, ivHex) {
	let data = Hex.parse(dataHex);
	let key = Hex.parse(keyHex);
	let iv = Hex.parse(ivHex);
	let encryptedHex = f.encrypt(data, key, { 'iv': iv });
	let encryptedWA = Hex.parse(encryptedHex.toString());
	let encryptedB64 = Base64.stringify(encryptedWA);
	return encryptedB64;
}

// shared key decryption ------------------------------------------
/**
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function decryptAES(dataHex, keyHex, ivHex) {
	return decryptGeneral(AES, dataHex, keyHex, ivHex);
}

/**
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function decrypt3DES(dataHex, keyHex, ivHex) {
	return decryptGeneral(TripleDES, dataHex, keyHex, ivHex);
}

/**
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function decryptDES(dataHex, keyHex, ivHex) {
	return decryptGeneral(DES, dataHex, keyHex, ivHex);
}

// shared key decryption ------------------------------------------
/**
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function encryptAES(dataHex, keyHex, ivHex) {
	return encryptGeneral(AES, dataHex, keyHex, ivHex);
}

/**
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function encrypt3DES(dataHex, keyHex, ivHex) {
	return encryptGeneral(TripleDES, dataHex, keyHex, ivHex);
}

/**
 * @param {string} dataHex 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string}
 */
function encryptDES(dataHex, keyHex, ivHex) {
	return encryptGeneral(DES, dataHex, keyHex, ivHex);
}

// other methods and properties ----------------------------------------

/** @typedef {function(string,string,string):string} ALGFunc */ var ALGFunc;

/** @typedef {{
	proc: ALGFunc,
	eproc: ALGFunc,
	keylen: number,
	ivlen: number
}} ALG */ var ALG;

/** @type {Object<string,ALG>} */
const ALGLIST = {
	'AES-256-CBC': { proc: decryptAES, eproc: encryptAES, keylen: 32, ivlen: 16 },
	'AES-192-CBC': { proc: decryptAES, eproc: encryptAES, keylen: 24, ivlen: 16 },
	'AES-128-CBC': { proc: decryptAES, eproc: encryptAES, keylen: 16, ivlen: 16 },
	'DES-EDE3-CBC': { proc: decrypt3DES, eproc: encrypt3DES, keylen: 24, ivlen: 8 },
	'DES-CBC': { proc: decryptDES, eproc: encryptDES, keylen: 8, ivlen: 8 }
};

/**
 * @param {string} algName 
 * @returns {ALGFunc}
 */
function getFuncByName(algName) {
	return ALGLIST[algName].proc;
}

/**
 * @param {number} numBytes 
 */
function generateIvSaltHex(numBytes) {
	let wa = WordArray.random(numBytes);
	let hex = Hex.stringify(wa);
	return hex;
}

/**
 * @param {string} privateKeyHex hexadecimal string of private key
 * @param {string} sharedKeyAlgName algorithm name of shared key encryption
 * @param {string} sharedKeyHex hexadecimal string of shared key to encrypt
 * @param {string} ivsaltHex hexadecimal string of IV and salt
 * @returns {string} base64 string of encrypted private key
 */
function encryptKeyHex(privateKeyHex, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
	let f = ALGLIST[sharedKeyAlgName].eproc;
	let encryptedKeyB64 = f(privateKeyHex, sharedKeyHex, ivsaltHex);
	return encryptedKeyB64;
}

// -- UTILITY METHODS ------------------------------------------------------------

/** @typedef {{
 cipher: (string | undefined),
 ivsalt: (string | undefined),
 type: (string | undefined),
 data: (string | undefined)
}} PKCS5PEM */ var PKCS5PEM;

/**
 * parse PEM formatted passcode protected PKCS#5 private key
 * @param {string} sPKCS5PEM PEM formatted protected passcode protected PKCS#5 private key
 * @return {PKCS5PEM} hash of key information
 * @description
 * Resulted hash has following attributes.
 * <ul>
 * <li>cipher - symmetric key algorithm name (ex. 'DES-EBE3-CBC', 'AES-256-CBC')</li>
 * <li>ivsalt - IV used for decrypt. Its heading 8 bytes will be used for passcode salt.</li>
 * <li>type - asymmetric key algorithm name of private key described in PEM header.</li>
 * <li>data - base64 encoded encrypted private key.</li>
 * </ul>
 *
 */
export function parsePKCS5PEM(sPKCS5PEM) {
	/** @type {PKCS5PEM} */ let info = {};
	let matchResult1 = sPKCS5PEM.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"));
	if (matchResult1) {
		info.cipher = matchResult1[1];
		info.ivsalt = matchResult1[2];
	}
	let matchResult2 = sPKCS5PEM.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"));
	if (matchResult2) {
		info.type = matchResult2[1];
	}
	let i1 = -1;
	let lenNEWLINE = 0;
	if (sPKCS5PEM.indexOf("\r\n\r\n") != -1) {
		i1 = sPKCS5PEM.indexOf("\r\n\r\n");
		lenNEWLINE = 2;
	}
	if (sPKCS5PEM.indexOf("\n\n") != -1) {
		i1 = sPKCS5PEM.indexOf("\n\n");
		lenNEWLINE = 1;
	}
	let i2 = sPKCS5PEM.indexOf("-----END");
	if (i1 != -1 && i2 != -1) {
		let s = sPKCS5PEM.substring(i1 + lenNEWLINE * 2, i2 - lenNEWLINE);
		s = s.replace(/\s+/g, '');
		info.data = s;
	}
	return info;
}

/** @typedef {{
 keyhex: string,
 ivhex: string
}} KEYANDUNUSEDIV */ var KEYANDUNUSEDIV;

/**
 * the same function as OpenSSL EVP_BytsToKey to generate shared key and IV
 * @param {string} algName name of symmetric key algorithm (ex. 'DES-EBE3-CBC')
 * @param {string} passcode passcode to decrypt private key (ex. 'password')
 * @param {string} ivsaltHex hexadecimal string of IV. heading 8 bytes will be used for passcode salt
 * @return {KEYANDUNUSEDIV} hash of key and unused IV (ex. {keyhex:2fe3..., ivhex:3fad..})
 */
export function getKeyAndUnusedIvByPasscodeAndIvsalt(algName, passcode, ivsaltHex) {
	//alert("ivsaltHex(2) = " + ivsaltHex);
	let saltHex = ivsaltHex.substring(0, 16);
	//alert("salt = " + saltHex);

	let salt = Hex.parse(saltHex);
	let data = Utf8.parse(passcode);
	//alert("salt = " + salt);
	//alert("data = " + data);

	let nRequiredBytes = ALGLIST[algName].keylen + ALGLIST[algName].ivlen;
	let hHexValueJoined = '';
	/** @type {WordArray | null} */ let hLastValue = null;
	//alert("nRequiredBytes = " + nRequiredBytes);
	for (; ;) {
		let h = new HasherMD5();
		if (hLastValue != null) {
			h.update(hLastValue);
		}
		h.update(data);
		h.update(salt);
		hLastValue = h.finalize();
		hHexValueJoined = hHexValueJoined + Hex.stringify(hLastValue);
		//alert("joined = " + hHexValueJoined);
		if (hHexValueJoined.length >= nRequiredBytes * 2) {
			break;
		}
	}
	return {
		keyhex: hHexValueJoined.substr(0, ALGLIST[algName].keylen * 2),
		ivhex: hHexValueJoined.substr(ALGLIST[algName].keylen * 2, ALGLIST[algName].ivlen * 2)
	}
}

/**
 * @param {string} privateKeyB64 base64 string of encrypted private key
 * @param {string} sharedKeyAlgName algorithm name of shared key encryption
 * @param {string} sharedKeyHex hexadecimal string of shared key to encrypt
 * @param {string} ivsaltHex hexadecimal string of IV and salt
 * @returns {string} hexadecimal string of decrypted private key
 */
export function decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex) {
	let privateKeyWA = Base64.parse(privateKeyB64);
	let privateKeyHex = Hex.stringify(privateKeyWA);
	let f = ALGLIST[sharedKeyAlgName].proc;
	let decryptedKeyHex = f(privateKeyHex, sharedKeyHex, ivsaltHex);
	return decryptedKeyHex;
}

/**
 * decrypt PEM formatted protected PKCS#5 private key with passcode
 * @param {string} sEncryptedPEM PEM formatted protected passcode protected PKCS#5 private key
 * @param {string} passcode passcode to decrypt private key (ex. 'password')
 * @return {string | null} hexadecimal string of decrypted RSA priavte key
 */
export function getDecryptedKeyHex(sEncryptedPEM, passcode) {
	// 1. parse pem
	let info = parsePKCS5PEM(sEncryptedPEM);
	let publicKeyAlgName = info.type;
	let sharedKeyAlgName = info.cipher;
	let ivsaltHex = info.ivsalt;
	let privateKeyB64 = info.data;
	if ((sharedKeyAlgName === undefined) || (ivsaltHex === undefined) || (privateKeyB64 === undefined)) return null;
	//alert("ivsaltHex = " + ivsaltHex);

	// 2. generate shared key
	let sharedKeyInfo = getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
	let sharedKeyHex = sharedKeyInfo.keyhex;
	//alert("sharedKeyHex = " + sharedKeyHex);

	// 3. decrypt private key
	let decryptedKey = decryptKeyB64(privateKeyB64, sharedKeyAlgName, sharedKeyHex, ivsaltHex);
	return decryptedKey;
}

/**
 * get PEM formatted encrypted PKCS#5 private key from hexadecimal string of plain private key
 * @param {string} pemHeadAlg algorithm name in the pem header (i.e. RSA,EC or DSA)
 * @param {string} hPrvKey hexadecimal string of plain private key
 * @param {string} passcode pass code to protect private key (ex. password)
 * @param {string} sharedKeyAlgName algorithm name to protect private key (ex. AES-256-CBC)
 * @param {string} ivsaltHex hexadecimal string of IV and salt
 * @return {string} string of PEM formatted encrypted PKCS#5 private key
 * @description
 * <br/>
 * generate PEM formatted encrypted PKCS#5 private key by hexadecimal string encoded
 * ASN.1 object of plain RSA private key.
 * Following arguments can be omitted.
 * <ul>
 * <li>alg - AES-256-CBC will be used if omitted.</li>
 * <li>ivsaltHex - automatically generate IV and salt which length depends on algorithm</li>
 * </ul>
 * NOTE1: DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC algorithm are supported.
 * @example
 * let pem = 
 *   getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password");
 * let pem2 = 
 *   getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC");
 * let pem3 = 
 *   getEncryptedPKCS5PEMFromPrvKeyHex(plainKeyHex, "password", "AES-128-CBC", "1f3d02...");
 */
export function getEncryptedPKCS5PEMFromPrvKeyHex(pemHeadAlg, hPrvKey, passcode, sharedKeyAlgName, ivsaltHex) {
	// 1. set sharedKeyAlgName if undefined (default AES-256-CBC)
	if (typeof sharedKeyAlgName == "undefined" || sharedKeyAlgName == null) {
		sharedKeyAlgName = "AES-256-CBC";
	}
	if (typeof ALGLIST[sharedKeyAlgName] == "undefined")
		throw "Unsupported algorithm: " + sharedKeyAlgName;

	// 2. set ivsaltHex if undefined
	if (typeof ivsaltHex == "undefined" || ivsaltHex == null) {
		let ivlen = ALGLIST[sharedKeyAlgName].ivlen;
		let randIV = generateIvSaltHex(ivlen);
		ivsaltHex = randIV.toUpperCase();
	}

	// 3. get shared key
	//alert("ivsalthex=" + ivsaltHex);
	let sharedKeyInfo = getKeyAndUnusedIvByPasscodeAndIvsalt(sharedKeyAlgName, passcode, ivsaltHex);
	let sharedKeyHex = sharedKeyInfo.keyhex;
	// alert("sharedKeyHex = " + sharedKeyHex);

	// 3. get encrypted Key in Base64
	let encryptedKeyB64 = encryptKeyHex(hPrvKey, sharedKeyAlgName, sharedKeyHex, ivsaltHex);

	let pemBody = encryptedKeyB64.replace(/(.{64})/g, "$1\r\n");
	let sPEM = "-----BEGIN " + pemHeadAlg + " PRIVATE KEY-----\r\n";
	sPEM += "Proc-Type: 4,ENCRYPTED\r\n";
	sPEM += "DEK-Info: " + sharedKeyAlgName + "," + ivsaltHex + "\r\n";
	sPEM += "\r\n";
	sPEM += pemBody;
	sPEM += "\r\n-----END " + pemHeadAlg + " PRIVATE KEY-----\r\n";

	return sPEM;
}

// === PKCS8 ===============================================================

/** @typedef {{
	ciphertext: string,
	encryptionSchemeAlg: string,
	encryptionSchemeIV: string,
	pbkdf2Salt: string,
	pbkdf2Iter: number
}} PKCS8 */ var PKCS8;

/**
 * generate PBKDF2 key hexstring with specified passcode and information
 * @param {string} sHEX passcode to decrypto private key
 * @return {PKCS8} info associative array of PKCS#8 parameters
 * @description
 * The associative array which is returned by this method has following properties:
 * <ul>
 * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
 * <li>info.pkbdf2Iter - iteration count</li>
 * <li>info.ciphertext - hexadecimal string of encrypted private key</li>
 * <li>info.encryptionSchemeAlg - encryption algorithm name (currently TripleDES only)</li>
 * <li>info.encryptionSchemeIV - initial vector for encryption algorithm</li>
 * </ul>
 * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
 * <ul>
 * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
 * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
 * </ul>
 * @example
 * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
 * // key with PBKDF2 with TripleDES
 * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
 */
export function parseHexOfEncryptedPKCS8(sHEX) {
	let a0 = getChildIdx(sHEX, 0);
	if (a0.length != 2)
		throw "malformed format: SEQUENCE(0).items != 2: " + a0.length;

	// 1. ciphertext
	let ciphertext = getV(sHEX, a0[1]);

	// 2. pkcs5PBES2
	let a0_0 = getChildIdx(sHEX, a0[0]);
	if (a0_0.length != 2)
		throw "malformed format: SEQUENCE(0.0).items != 2: " + a0_0.length;

	// 2.1 check if pkcs5PBES2(1 2 840 113549 1 5 13)
	if (getV(sHEX, a0_0[0]) != "2a864886f70d01050d")
		throw "this only supports pkcs5PBES2";

	// 2.2 pkcs5PBES2 param
	let a0_0_1 = getChildIdx(sHEX, a0_0[1]);
	if (a0_0.length != 2)
		throw "malformed format: SEQUENCE(0.0.1).items != 2: " + a0_0_1.length;

	// 2.2.1 encryptionScheme
	let a0_0_1_1 = getChildIdx(sHEX, a0_0_1[1]);
	if (a0_0_1_1.length != 2)
		throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + a0_0_1_1.length;
	if (getV(sHEX, a0_0_1_1[0]) != "2a864886f70d0307")
		throw "this only supports TripleDES";
	let encryptionSchemeAlg = "TripleDES";

	// 2.2.1.1 IV of encryptionScheme
	let encryptionSchemeIV = getV(sHEX, a0_0_1_1[1]);

	// 2.2.2 keyDerivationFunc
	let a0_0_1_0 = getChildIdx(sHEX, a0_0_1[0]);
	if (a0_0_1_0.length != 2)
		throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + a0_0_1_0.length;
	if (getV(sHEX, a0_0_1_0[0]) != "2a864886f70d01050c")
		throw "this only supports pkcs5PBKDF2";

	// 2.2.2.1 pkcs5PBKDF2 param
	let a0_0_1_0_1 = getChildIdx(sHEX, a0_0_1_0[1]);
	if (a0_0_1_0_1.length < 2)
		throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + a0_0_1_0_1.length;

	// 2.2.2.1.1 PBKDF2 salt
	let pbkdf2Salt = getV(sHEX, a0_0_1_0_1[0]);

	// 2.2.2.1.2 PBKDF2 iter
	let iterNumHex = getV(sHEX, a0_0_1_0_1[1]);
	/** @type {number} */ let pbkdf2Iter;
	try {
		pbkdf2Iter = parseInt(iterNumHex, 16);
	} catch (ex) {
		throw "malformed format pbkdf2Iter: " + iterNumHex;
	}

	return {
		ciphertext: ciphertext,
		encryptionSchemeAlg: encryptionSchemeAlg,
		encryptionSchemeIV: encryptionSchemeIV,
		pbkdf2Salt: pbkdf2Salt,
		pbkdf2Iter: pbkdf2Iter
	};
}

/**
 * generate PBKDF2 key hexstring with specified passcode and information
 * @param {PKCS8} info result of {@link parseHexOfEncryptedPKCS8} which has preference of PKCS#8 file
 * @param {string} passcode passcode to decrypto private key
 * @return {string} hexadecimal string of PBKDF2 key
 * @description
 * As for info, this uses following properties:
 * <ul>
 * <li>info.pbkdf2Salt - hexadecimal string of PBKDF2 salt</li>
 * <li>info.pkbdf2Iter - iteration count</li>
 * </ul>
 * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
 * <ul>
 * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
 * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
 * </ul>
 * @example
 * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
 * // key with PBKDF2 with TripleDES
 * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
 */
export function getPBKDF2KeyHexFromParam(info, passcode) {
	let pbkdf2SaltWS = Hex.parse(info.pbkdf2Salt);
	let pbkdf2Iter = info.pbkdf2Iter;
	let pbkdf2KeyWS = PBKDF2(passcode, pbkdf2SaltWS, { 'keySize': 192 / 32, 'iterations': pbkdf2Iter });
	let pbkdf2KeyHex = Hex.stringify(pbkdf2KeyWS);
	return pbkdf2KeyHex;
}

/**
 * read PEM formatted encrypted PKCS#8 private key and returns hexadecimal string of plain PKCS#8 private key
 * @param {string} pkcs8PEM PEM formatted encrypted PKCS#8 private key
 * @param {string} passcode passcode to decrypto private key
 * @return {string} hexadecimal string of plain PKCS#8 private key
 * @description
 * Currently, this method only supports PKCS#5v2.0 with PBES2/PBDKF2 of HmacSHA1 and TripleDES.
 * <ul>
 * <li>keyDerivationFunc = pkcs5PBKDF2 with HmacSHA1</li>
 * <li>encryptionScheme = des-EDE3-CBC(i.e. TripleDES</li>
 * </ul>
 * @example
 * // to convert plain PKCS#5 private key to encrypted PKCS#8 private
 * // key with PBKDF2 with TripleDES
 * % openssl pkcs8 -in plain_p5.pem -topk8 -v2 -des3 -out encrypted_p8.pem
 */
export function getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode) {
	// 1. derHex - PKCS#8 private key encrypted by PBKDF2
	let derHex = pemtohex(pkcs8PEM, "ENCRYPTED PRIVATE KEY");
	// 2. info - PKCS#5 PBES info
	let info = parseHexOfEncryptedPKCS8(derHex);
	// 3. hKey - PBKDF2 key
	let pbkdf2KeyHex = getPBKDF2KeyHexFromParam(info, passcode);
	// 4. decrypt ciphertext by PBKDF2 key
	/** @dict */
	let encrypted = {};
	encrypted['ciphertext'] = Hex.parse(info.ciphertext);
	let pbkdf2KeyWS = Hex.parse(pbkdf2KeyHex);
	let des3IVWS = Hex.parse(info.encryptionSchemeIV);
	let decWS = TripleDES.decrypt(encrypted, pbkdf2KeyWS, { 'iv': des3IVWS });
	let decHex = Hex.stringify(decWS);
	return decHex;
}

/**
 * get RSAKeyEx/ECDSA private key object from encrypted PEM PKCS#8 private key
 * @param {string} pkcs8PEM string of PEM formatted PKCS#8 private key
 * @param {string} passcode passcode string to decrypt key
 * @return {KeyObject} RSAKeyEx or ECDSA private key object
 */
export function getKeyFromEncryptedPKCS8PEM(pkcs8PEM, passcode) {
	let prvKeyHex = getPlainPKCS8HexFromEncryptedPKCS8PEM(pkcs8PEM, passcode);
	let key = getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
	return key;
}

/** @typedef {{
	algparam: (string | null),
	algoid: string,
	keyidx: number
}} PlainPrivatePKCS8 */ var PlainPrivatePKCS8;

/**
 * parse hexadecimal string of plain PKCS#8 private key
 * @param {string} pkcs8PrvHex hexadecimal string of PKCS#8 plain private key
 * @return {PlainPrivatePKCS8} associative array of parsed key
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
 * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
 * <li>keyidx - string starting index of key in pkcs8PrvHex</li>
 * </ul>
 */
export function parsePlainPrivatePKCS8Hex(pkcs8PrvHex) {
	/** @type {string | null} */ let algparam = null;

	// 1. sequence
	if (pkcs8PrvHex.substr(0, 2) != "30")
		throw "malformed plain PKCS8 private key(code:001)"; // not sequence

	let a1 = getChildIdx(pkcs8PrvHex, 0);
	if (a1.length != 3)
		throw "malformed plain PKCS8 private key(code:002)";

	// 2. AlgID
	if (pkcs8PrvHex.substr(a1[1], 2) != "30")
		throw "malformed PKCS8 private key(code:003)"; // AlgId not sequence

	let a2 = getChildIdx(pkcs8PrvHex, a1[1]);
	if (a2.length != 2)
		throw "malformed PKCS8 private key(code:004)"; // AlgId not have two elements

	// 2.1. AlgID OID
	if (pkcs8PrvHex.substr(a2[0], 2) != "06")
		throw "malformed PKCS8 private key(code:005)"; // AlgId.oid is not OID

	let algoid = getV(pkcs8PrvHex, a2[0]);

	// 2.2. AlgID param
	if (pkcs8PrvHex.substr(a2[1], 2) == "06") {
		algparam = getV(pkcs8PrvHex, a2[1]);
	}

	// 3. Key index
	if (pkcs8PrvHex.substr(a1[2], 2) != "04")
		throw "malformed PKCS8 private key(code:006)"; // not octet string

	let keyidx = getVidx(pkcs8PrvHex, a1[2]);

	return {
		algparam: algparam,
		algoid: algoid,
		keyidx: keyidx
	};
}

/**
 * get RSAKeyEx/ECDSA private key object from PEM plain PEM PKCS#8 private key
 * @param {string} pkcs8PEM string of plain PEM formatted PKCS#8 private key
 * @return {KeyObject} RSAKeyEx or ECDSA private key object
 */
export function getKeyFromPlainPrivatePKCS8PEM(prvKeyPEM) {
	let prvKeyHex = pemtohex(prvKeyPEM, "PRIVATE KEY");
	let key = getKeyFromPlainPrivatePKCS8Hex(prvKeyHex);
	return key;
}

/**
 * get RSAKeyEx/DSA/ECDSA private key object from HEX plain PEM PKCS#8 private key
 * @param {string} prvKeyHex hexadecimal string of plain PKCS#8 private key
 * @return {KeyObject} RSAKeyEx or DSA or ECDSA private key object
 */
export function getKeyFromPlainPrivatePKCS8Hex(prvKeyHex) {
	let p8 = parsePlainPrivatePKCS8Hex(prvKeyHex);
	let key;

	if (p8.algoid == "2a864886f70d010101") { // RSA
		key = new RSAKeyEx();
	} else if (p8.algoid == "2a8648ce380401") { // DSA
		key = new DSA();
	} else if (p8.algoid == "2a8648ce3d0201") { // ECC
		key = new ECDSA();
	} else {
		throw "unsupported private key algorithm";
	}

	key.readPKCS8PrvKeyHex(prvKeyHex);
	return key;
}

// === PKCS8 RSA Public Key ================================================

/**
 * get RSAKeyEx/DSA/ECDSA public key object from hexadecimal string of PKCS#8 public key
 * @param {string} pkcsPub8Hex hexadecimal string of PKCS#8 public key
 * @return {KeyObject} RSAKeyEx or ECDSA or DSA private key object
 */
export function getKeyFromPublicPKCS8Hex(h) {
	let key;
	let hOID = getVbyList(h, 0, [0, 0], "06");

	if (hOID === "2a864886f70d010101") {    // oid=RSA
		key = new RSAKeyEx();
	} else if (hOID === "2a8648ce380401") { // oid=DSA
		key = new DSA();
	} else if (hOID === "2a8648ce3d0201") { // oid=ECPUB
		key = new ECDSA();
	} else {
		throw "unsupported PKCS#8 public key hex";
	}
	key.readPKCS8PubKeyHex(h);
	return key;
}

/** @typedef {{
	n: string,
	e: string
}} PublicRawRSAKeyEx */ var PublicRawRSAKeyEx

/**
 * parse hexadecimal string of plain PKCS#8 private key
 * @param {string} pubRawRSAHex hexadecimal string of ASN.1 encoded PKCS#8 public key
 * @return {PublicRawRSAKeyEx} associative array of parsed key
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>n - hexadecimal string of public key
 * <li>e - hexadecimal string of public exponent
 * </ul>
 */
export function parsePublicRawRSAKeyExHex(pubRawRSAHex) {
	// 1. Sequence
	if (pubRawRSAHex.substr(0, 2) != "30")
		throw "malformed RSA key(code:001)"; // not sequence

	let a1 = getChildIdx(pubRawRSAHex, 0);
	if (a1.length != 2)
		throw "malformed RSA key(code:002)"; // not 2 items in seq

	// 2. public key "N"
	if (pubRawRSAHex.substr(a1[0], 2) != "02")
		throw "malformed RSA key(code:003)"; // 1st item is not integer

	let n = getV(pubRawRSAHex, a1[0]);

	// 3. public key "E"
	if (pubRawRSAHex.substr(a1[1], 2) != "02")
		throw "malformed RSA key(code:004)"; // 2nd item is not integer

	let e = getV(pubRawRSAHex, a1[1]);

	return { n: n, e: e };
}

/** @typedef {{
	p: string,
	q: string,
	g: string
}} PublicPKCS8AlgParam */ var PublicPKCS8AlgParam;

/** @typedef {{
	algparam: (string | PublicPKCS8AlgParam | null),
	algoid: string,
	key: string
}} PublicPKCS8 */ var PublicPKCS8;

/**
 * parse hexadecimal string of PKCS#8 RSA/EC/DSA public key
 * @param {string} pkcs8PubHex hexadecimal string of PKCS#8 public key
 * @return {PublicPKCS8} hash of key information
 * @description
 * Resulted hash has following attributes.
 * <ul>
 * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
 * <li>algparam - hexadecimal string of OID of ECC curve name, parameter SEQUENCE of DSA or null</li>
 * <li>key - hexadecimal string of public key</li>
 * </ul>
 */
export function parsePublicPKCS8Hex(pkcs8PubHex) {
	/** @type {string | PublicPKCS8AlgParam | null} */ let algparam = null;

	// 1. AlgID and Key bit string
	let a1 = getChildIdx(pkcs8PubHex, 0);
	if (a1.length != 2)
		throw "outer DERSequence shall have 2 elements: " + a1.length;

	// 2. AlgID
	let idxAlgIdTLV = a1[0];
	if (pkcs8PubHex.substr(idxAlgIdTLV, 2) != "30")
		throw "malformed PKCS8 public key(code:001)"; // AlgId not sequence

	let a2 = getChildIdx(pkcs8PubHex, idxAlgIdTLV);
	if (a2.length != 2)
		throw "malformed PKCS8 public key(code:002)"; // AlgId not have two elements

	// 2.1. AlgID OID
	if (pkcs8PubHex.substr(a2[0], 2) != "06")
		throw "malformed PKCS8 public key(code:003)"; // AlgId.oid is not OID

	let algoid = getV(pkcs8PubHex, a2[0]);

	// 2.2. AlgID param
	if (pkcs8PubHex.substr(a2[1], 2) == "06") { // OID for EC
		algparam = getV(pkcs8PubHex, a2[1]);
	} else if (pkcs8PubHex.substr(a2[1], 2) == "30") { // SEQ for DSA
		algparam = {
			p: getVbyList(pkcs8PubHex, a2[1], [0], "02"),
			q: getVbyList(pkcs8PubHex, a2[1], [1], "02"),
			g: getVbyList(pkcs8PubHex, a2[1], [2], "02")
		};
	}

	// 3. Key
	if (pkcs8PubHex.substr(a1[1], 2) != "03")
		throw "malformed PKCS8 public key(code:004)"; // Key is not bit string

	let key = getV(pkcs8PubHex, a1[1]).substr(2);

	// 4. return result assoc array
	return {
		algparam: algparam,
		algoid: algoid,
		key: key
	};
}

/**
 * get private or public key object from any arguments
 * @param {string | RSAKeyEx | DSA | ECDSA | Object<string,*>} param parameter to get key object. see description in detail.
 * @param {string=} passcode (OPTION) parameter to get key object. see description in detail.
 * @param {string=} hextype (OPTOIN) parameter to get key object. see description in detail.
 * @return {KeyObject} object {@link RSAKeyEx}, {@link ECDSA} or {@link ECDSA}
 * @description
 * This method gets private or public key object({@link RSAKeyEx}, {@link DSA} or {@link ECDSA})
 * for RSA, DSA and ECC.
 * Arguments for this methods depends on a key format you specify.
 * Following key representations are supported.
 * <ul>
 * <li>ECC private/public key object(as is): param=ECDSA</li>
 * <li>DSA private/public key object(as is): param=DSA</li>
 * <li>RSA private/public key object(as is): param=RSAKeyEx </li>
 * <li>ECC private key parameters: param={d: d, curve: curveName}</li>
 * <li>RSA private key parameters: param={n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, co: co}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>DSA private key parameters: param={p: p, q: q, g: g, y: y, x: x}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>ECC public key parameters: param={xy: xy, curve: curveName}<br/>
 * NOTE: ECC public key 'xy' shall be concatination of "04", x-bytes-hex and y-bytes-hex.</li>
 * <li>DSA public key parameters: param={p: p, q: q, g: g, y: y}<br/>
 * NOTE: Each value shall be hexadecimal string of key spec.</li>
 * <li>RSA public key parameters: param={n: n, e: e} </li>
 * <li>X.509v1/v3 PEM certificate (RSA/DSA/ECC): param=pemString</li>
 * <li>PKCS#8 hexadecimal RSA/ECC public key: param=pemString, null, "pkcs8pub"</li>
 * <li>PKCS#8 PEM RSA/DSA/ECC public key: param=pemString</li>
 * <li>PKCS#5 plain hexadecimal RSA private key: param=hexString, null, "pkcs5prv"</li>
 * <li>PKCS#5 plain PEM DSA/RSA private key: param=pemString</li>
 * <li>PKCS#8 plain PEM RSA/ECDSA private key: param=pemString</li>
 * <li>PKCS#5 encrypted PEM RSA/DSA private key: param=pemString, passcode</li>
 * <li>PKCS#8 encrypted PEM RSA/ECDSA private key: param=pemString, passcode</li>
 * </ul>
 * Please note following limitation on encrypted keys:
 * <ul>
 * <li>Encrypted PKCS#8 only supports PBKDF2/HmacSHA1/3DES</li>
 * <li>Encrypted PKCS#5 supports DES-CBC, DES-EDE3-CBC, AES-{128,192.256}-CBC</li>
 * <li>JWT plain ECC private/public key</li>
 * <li>JWT plain RSA public key</li>
 * <li>JWT plain RSA private key with P/Q/DP/DQ/COEFF</li>
 * <li>JWT plain RSA private key without P/Q/DP/DQ/COEFF (since jsrsasign 5.0.0)</li>
 * </ul>
 * NOTE1: <a href="https://tools.ietf.org/html/rfc7517">RFC 7517 JSON Web Key(JWK)</a> support for RSA/ECC private/public key from jsrsasign 4.8.1.<br/>
 * NOTE2: X509v1 support is added since jsrsasign 5.0.11.
 * 
 * <h5>EXAMPLE</h5>
 * @example
 * // 1. loading private key from PEM string
 * keyObj = getKey("-----BEGIN RSA PRIVATE KEY...");
 * keyObj = getKey("-----BEGIN RSA PRIVATE KEY..., "passcode");
 * keyObj = getKey("-----BEGIN PRIVATE KEY...");
 * keyObj = getKey("-----BEGIN PRIVATE KEY...", "passcode");
 * // 2. loading public key from PEM string
 * keyObj = getKey("-----BEGIN PUBLIC KEY...");
 * keyObj = getKey("-----BEGIN X509 CERTIFICATE...");
 * // 3. loading hexadecimal PKCS#5/PKCS#8 key
 * keyObj = getKey("308205c1...", null, "pkcs8pub");
 * keyObj = getKey("3082048b...", null, "pkcs5prv");
 * // 4. loading JSON Web Key(JWK)
 * keyObj = getKey({'kty': "RSA", 'n': "0vx7...", 'e': "AQAB"});
 * keyObj = getKey({'kty': "EC", 'crv': "P-256", 
 *                          'x': "MKBC...", 'y': "4Etl6...", 'd': "870Mb..."});
 * // 5. bare hexadecimal key
 * keyObj = getKey({'n': "75ab..", 'e': "010001"});
 */
export function getKey(param, passcode, hextype) {
	// 1. by key RSAKeyEx/ECDSA/DSA object
	if (typeof RSAKeyEx != 'undefined' && param instanceof RSAKeyEx)
		return param;
	if (typeof ECDSA != 'undefined' && param instanceof ECDSA)
		return param;
	if (typeof DSA != 'undefined' && param instanceof DSA)
		return param;

	// 2. by parameters of key

	// 2.1. bare ECC
	// 2.1.1. bare ECC public key by hex values
	if (param['curve'] !== undefined &&
		param['xy'] !== undefined && param['d'] === undefined) {
		return new ECDSA({ 'pub': param['xy'], 'curve': param['curve'] });
	}

	// 2.1.2. bare ECC private key by hex values
	if (param['curve'] !== undefined && param['d'] !== undefined) {
		return new ECDSA({ 'prv': param['d'], 'curve': param['curve'] });
	}

	// 2.2. bare RSA
	// 2.2.1. bare RSA public key by hex values
	if (param['kty'] === undefined &&
		param['n'] !== undefined && param['e'] !== undefined &&
		param['d'] === undefined) {
		let key = new RSAKeyEx();
		key.setPublic(param['n'], param['e']);
		return key;
	}

	// 2.2.2. bare RSA private key with P/Q/DP/DQ/COEFF by hex values
	if (param['kty'] === undefined &&
		param['n'] !== undefined &&
		param['e'] !== undefined &&
		param['d'] !== undefined &&
		param['p'] !== undefined &&
		param['q'] !== undefined &&
		param['dp'] !== undefined &&
		param['dq'] !== undefined &&
		param['co'] !== undefined &&
		param['qi'] === undefined) {
		let key = new RSAKeyEx();
		key.setPrivateEx(param['n'], param['e'], param['d'], param['p'], param['q'],
			param['dp'], param['dq'], param['co']);
		return key;
	}

	// 2.2.3. bare RSA public key without P/Q/DP/DQ/COEFF by hex values
	if (param['kty'] === undefined &&
		param['n'] !== undefined &&
		param['e'] !== undefined &&
		param['d'] !== undefined &&
		param['p'] === undefined) {
		let key = new RSAKeyEx();
		key.setPrivate(param['n'], param['e'], param['d']);
		return key;
	}

	// 2.3. bare DSA
	// 2.3.1. bare DSA public key by hex values
	if (param['p'] !== undefined && param['q'] !== undefined &&
		param['g'] !== undefined &&
		param['y'] !== undefined && param['x'] === undefined) {
		let key = new DSA();
		key.setPublic(param['p'], param['q'], param['g'], param['y']);
		return key;
	}

	// 2.3.2. bare DSA private key by hex values
	if (param['p'] !== undefined && param['q'] !== undefined &&
		param['g'] !== undefined &&
		param['y'] !== undefined && param['x'] !== undefined) {
		let key = new DSA();
		key.setPrivate(param['p'], param['q'], param['g'], param['y'], param['x']);
		return key;
	}

	// 3. JWK
	// 3.1. JWK RSA
	// 3.1.1. JWK RSA public key by b64u values
	if (param['kty'] === "RSA" &&
		param['n'] !== undefined &&
		param['e'] !== undefined &&
		param['d'] === undefined) {
		let key = new RSAKeyEx();
		key.setPublic(b64utohex(param['n']), b64utohex(param['e']));
		return key;
	}

	// 3.1.2. JWK RSA private key with p/q/dp/dq/coeff by b64u values
	if (param['kty'] === "RSA" &&
		param['n'] !== undefined &&
		param['e'] !== undefined &&
		param['d'] !== undefined &&
		param['p'] !== undefined &&
		param['q'] !== undefined &&
		param['dp'] !== undefined &&
		param['dq'] !== undefined &&
		param['qi'] !== undefined) {
		let key = new RSAKeyEx();
		key.setPrivateEx(b64utohex(param['n']),
			b64utohex(param['e']),
			b64utohex(param['d']),
			b64utohex(param['p']),
			b64utohex(param['q']),
			b64utohex(param['dp']),
			b64utohex(param['dq']),
			b64utohex(param['qi']));
		return key;
	}

	// 3.1.3. JWK RSA private key without p/q/dp/dq/coeff by b64u
	//        since jsrsasign 5.0.0 keyutil 1.0.11
	if (param['kty'] === "RSA" &&
		param['n'] !== undefined &&
		param['e'] !== undefined &&
		param['d'] !== undefined) {
		let key = new RSAKeyEx();
		key.setPrivate(b64utohex(param['n']),
			b64utohex(param['e']),
			b64utohex(param['d']));
		return key;
	}

	// 3.2. JWK ECC
	// 3.2.1. JWK ECC public key by b64u values
	if (param['kty'] === "EC" &&
		param['crv'] !== undefined &&
		param['x'] !== undefined &&
		param['y'] !== undefined &&
		param['d'] === undefined) {
		let ec = new ECDSA({ "curve": param['crv'] });
		let charlen = ec.ecparams.keylen / 4;
		let hX = ("0000000000" + b64utohex(param['x'])).slice(- charlen);
		let hY = ("0000000000" + b64utohex(param['y'])).slice(- charlen);
		let hPub = "04" + hX + hY;
		ec.setPublicKeyHex(hPub);
		return ec;
	}

	// 3.2.2. JWK ECC private key by b64u values
	if (param['kty'] === "EC" &&
		param['crv'] !== undefined &&
		param['x'] !== undefined &&
		param['y'] !== undefined &&
		param['d'] !== undefined) {
		let ec = new ECDSA({ "curve": param['crv'] });
		let charlen = ec.ecparams.keylen / 4;
		let hX = ("0000000000" + b64utohex(param['x'])).slice(- charlen);
		let hY = ("0000000000" + b64utohex(param['y'])).slice(- charlen);
		let hPub = "04" + hX + hY;
		let hPrv = ("0000000000" + b64utohex(param['d'])).slice(- charlen);
		ec.setPublicKeyHex(hPub);
		ec.setPrivateKeyHex(hPrv);
		return ec;
	}

	// 4. (plain) hexadecimal data
	// 4.1. get private key by PKCS#5 plain RSA/DSA/ECDSA hexadecimal string
	if (hextype === "pkcs5prv") {
		let h = param;
		let a = getChildIdx(h, 0);
		/** @type {KeyObject} */ let key;
		if (a.length === 9) {        // RSA (INT x 9)
			key = new RSAKeyEx();
			key.readPKCS5PrvKeyHex(h);
		} else if (a.length === 6) { // DSA (INT x 6)
			key = new DSA();
			key.readPKCS5PrvKeyHex(h);
		} else if (a.length > 2 &&   // ECDSA (INT, OCT prv, [0] curve, [1] pub)
			h.substr(a[1], 2) === "04") {
			key = new ECDSA();
			key.readPKCS5PrvKeyHex(h);
		} else {
			throw "unsupported PKCS#1/5 hexadecimal key";
		}

		return key;
	}

	// 4.2. get private key by PKCS#8 plain RSA/DSA/ECDSA hexadecimal string
	if (hextype === "pkcs8prv") {
		let key = getKeyFromPlainPrivatePKCS8Hex(param);
		return key;
	}

	// 4.3. get public key by PKCS#8 RSA/DSA/ECDSA hexadecimal string
	if (hextype === "pkcs8pub") {
		return getKeyFromPublicPKCS8Hex(param);
	}

	// 4.4. get public key by X.509 hexadecimal string for RSA/DSA/ECDSA
	if (hextype === "x509pub") {
		return getPublicKeyFromCertHex(param);
	}

	// 5. by PEM certificate (-----BEGIN ... CERTIFICATE----)
	if (param.indexOf("-END CERTIFICATE-", 0) != -1 ||
		param.indexOf("-END X509 CERTIFICATE-", 0) != -1 ||
		param.indexOf("-END TRUSTED CERTIFICATE-", 0) != -1) {
		return getPublicKeyFromCertPEM(param);
	}

	// 6. public key by PKCS#8 PEM string
	if (param.indexOf("-END PUBLIC KEY-") != -1) {
		let pubKeyHex = pemtohex(param, "PUBLIC KEY");
		return getKeyFromPublicPKCS8Hex(pubKeyHex);
	}

	// 8.1 private key by plain PKCS#5 PEM RSA string 
	//    getKey("-----BEGIN RSA PRIVATE KEY-...")
	if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
		param.indexOf("4,ENCRYPTED") == -1) {
		let hex = pemtohex(param, "RSA PRIVATE KEY");
		return getKey(hex, null, "pkcs5prv");
	}

	// 8.2. private key by plain PKCS#5 PEM DSA string
	if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
		param.indexOf("4,ENCRYPTED") == -1) {

		let hKey = pemtohex(param, "DSA PRIVATE KEY");
		let p = getVbyList(hKey, 0, [1], "02");
		let q = getVbyList(hKey, 0, [2], "02");
		let g = getVbyList(hKey, 0, [3], "02");
		let y = getVbyList(hKey, 0, [4], "02");
		let x = getVbyList(hKey, 0, [5], "02");
		let key = new DSA();
		key.setPrivate(new BigInteger(p, 16),
			new BigInteger(q, 16),
			new BigInteger(g, 16),
			new BigInteger(y, 16),
			new BigInteger(x, 16));
		return key;
	}

	// 10. private key by plain PKCS#8 PEM ECC/RSA string
	if (param.indexOf("-END PRIVATE KEY-") != -1) {
		return getKeyFromPlainPrivatePKCS8PEM(param);
	}

	// 11.1 private key by encrypted PKCS#5 PEM RSA string
	if (param.indexOf("-END RSA PRIVATE KEY-") != -1 &&
		param.indexOf("4,ENCRYPTED") != -1) {
		let hPKey = getDecryptedKeyHex(param, passcode);
		let rsaKey = new RSAKeyEx();
		rsaKey.readPKCS5PrvKeyHex(hPKey);
		return rsaKey;
	}

	// 11.2. private key by encrypted PKCS#5 PEM ECDSA string
	if (param.indexOf("-END EC PRIVATE KEY-") != -1 &&
		param.indexOf("4,ENCRYPTED") != -1) {
		let hKey = getDecryptedKeyHex(param, passcode);

		let key = getVbyList(hKey, 0, [1], "04");
		let curveNameOidHex = getVbyList(hKey, 0, [2, 0], "06");
		let pubkey = getVbyList(hKey, 0, [3, 0], "03").substr(2);
		let curveName = "";

		if (oidhex2name[curveNameOidHex] !== undefined) {
			curveName = oidhex2name[curveNameOidHex];
		} else {
			throw "undefined OID(hex): " + curveNameOidHex;
		}

		let ec = new ECDSA({ 'curve': curveName });
		ec.setPublicKeyHex(pubkey);
		ec.setPrivateKeyHex(key);
		ec.isPublic = false;
		return ec;
	}

	// 11.3. private key by encrypted PKCS#5 PEM DSA string
	if (param.indexOf("-END DSA PRIVATE KEY-") != -1 &&
		param.indexOf("4,ENCRYPTED") != -1) {
		let hKey = getDecryptedKeyHex(param, passcode);
		let p = getVbyList(hKey, 0, [1], "02");
		let q = getVbyList(hKey, 0, [2], "02");
		let g = getVbyList(hKey, 0, [3], "02");
		let y = getVbyList(hKey, 0, [4], "02");
		let x = getVbyList(hKey, 0, [5], "02");
		let key = new DSA();
		key.setPrivate(new BigInteger(p, 16),
			new BigInteger(q, 16),
			new BigInteger(g, 16),
			new BigInteger(y, 16),
			new BigInteger(x, 16));
		return key;
	}

	// 11. private key by encrypted PKCS#8 hexadecimal RSA/ECDSA string
	if (param.indexOf("-END ENCRYPTED PRIVATE KEY-") != -1) {
		return getKeyFromEncryptedPKCS8PEM(param, passcode);
	}

	throw "not supported argument";
}

/** @typedef {{
	prvKeyObj: (RSAKeyEx | ECDSA),
	pubKeyObj: (RSAKeyEx | ECDSA)
}} Keypair */ export var Keypair;

/**
 * @param {string} alg 'RSA' or 'EC'
 * @param {number | string} keylenOrCurve key length for RSA or curve name for EC
 * @return {Keypair} associative array of keypair which has prvKeyObj and pubKeyObj parameters
 * @description
 * This method generates a key pair of public key algorithm.
 * The result will be an associative array which has following
 * parameters:
 * <ul>
 * <li>prvKeyObj - RSAKeyEx or ECDSA object of private key</li>
 * <li>pubKeyObj - RSAKeyEx or ECDSA object of public key</li>
 * </ul>
 * NOTE1: As for RSA algoirthm, public exponent has fixed
 * value '0x10001'.
 * NOTE2: As for EC algorithm, supported names of curve are
 * secp256r1, secp256k1 and secp384r1.
 * NOTE3: DSA is not supported yet.
 * @example
 * let rsaKeypair = generateKeypair("RSA", 1024);
 * let ecKeypair = generateKeypair("EC", "secp256r1");
 *
 */
export function generateKeypair(alg, keylenOrCurve) {
	if (alg == "RSA") {
		let keylen = keylenOrCurve | 0;
		let prvKey = new RSAKeyEx();
		prvKey.generate(keylen, '10001');
		prvKey.isPrivate = true;
		prvKey.isPublic = true;

		let pubKey = new RSAKeyEx();
		let hN = prvKey.n.toString(16);
		let hE = prvKey.e.toString(16);
		pubKey.setPublic(hN, hE);
		pubKey.isPrivate = false;
		pubKey.isPublic = true;

		return {
			prvKeyObj: prvKey,
			pubKeyObj: pubKey
		}
	} else if (alg == "EC") {
		let curve = keylenOrCurve;
		let ec = new ECDSA({ curve: curve });
		let keypairHex = ec.generateKeyPairHex();

		let prvKey = new ECDSA({ curve: curve });
		prvKey.setPublicKeyHex(keypairHex.ecpubhex);
		prvKey.setPrivateKeyHex(keypairHex.ecprvhex);
		prvKey.isPrivate = true;
		prvKey.isPublic = false;

		let pubKey = new ECDSA({ curve: curve });
		pubKey.setPublicKeyHex(keypairHex.ecpubhex);
		pubKey.isPrivate = false;
		pubKey.isPublic = true;

		return {
			prvKeyObj: prvKey,
			pubKeyObj: pubKey
		}
	} else {
		throw "unknown algorithm: " + alg;
	}
}

/**
 * @param {RSAKeyEx} keyObjOrHex 
 * @returns {ASN1Object}
 */
function rsaprv2asn1obj(keyObjOrHex) {
	let asn1Obj = newObject({
		"seq": [
			{ "int": 0 },
			{ "int": { "bigint": keyObjOrHex.n } },
			{ "int": keyObjOrHex.e },
			{ "int": { "bigint": keyObjOrHex.d } },
			{ "int": { "bigint": keyObjOrHex.p } },
			{ "int": { "bigint": keyObjOrHex.q } },
			{ "int": { "bigint": keyObjOrHex.dmp1 } },
			{ "int": { "bigint": keyObjOrHex.dmq1 } },
			{ "int": { "bigint": keyObjOrHex.coeff } }
		]
	});
	return asn1Obj;
}

/**
 * @param {ECDSA} keyObjOrHex 
 * @returns {ASN1Object}
 */
function ecdsaprv2asn1obj(keyObjOrHex) {
	let asn1Obj2 = newObject({
		"seq": [
			{ "int": 1 },
			{ "octstr": { "hex": keyObjOrHex.prvKeyHex } },
			{ "tag": ['a0', true, { 'oid': { 'name': keyObjOrHex.curveName } }] },
			{ "tag": ['a1', true, { 'bitstr': { 'hex': '00' + keyObjOrHex.pubKeyHex } }] }
		]
	});
	return asn1Obj2;
}

/**
 * @param {DSA} keyObjOrHex 
 * @returns {ASN1Object}
 */
function dsaprv2asn1obj(keyObjOrHex) {
	let asn1Obj = newObject({
		"seq": [
			{ "int": 0 },
			{ "int": { "bigint": keyObjOrHex.p } },
			{ "int": { "bigint": keyObjOrHex.q } },
			{ "int": { "bigint": keyObjOrHex.g } },
			{ "int": { "bigint": keyObjOrHex.y } },
			{ "int": { "bigint": keyObjOrHex.x } }
		]
	});
	return asn1Obj;
}

/**
 * 
 * @param {string} plainKeyHex 
 * @param {string | WordArray} passcode 
 * @returns {ASN1Object}
 */
function getEncryptedPKCS8(plainKeyHex, passcode) {
	let info = getEencryptedPKCS8Info(plainKeyHex, passcode);
	//alert("iv=" + info.encryptionSchemeIV);
	//alert("info.ciphertext2[" + info.ciphertext.length + "=" + info.ciphertext);
	let asn1Obj = new newObject({
		"seq": [
			{
				"seq": [
					{ "oid": { "name": "pkcs5PBES2" } },
					{
						"seq": [
							{
								"seq": [
									{ "oid": { "name": "pkcs5PBKDF2" } },
									{
										"seq": [
											{ "octstr": { "hex": info.pbkdf2Salt } },
											{ "int": info.pbkdf2Iter }
										]
									}
								]
							},
							{
								"seq": [
									{ "oid": { "name": "des-EDE3-CBC" } },
									{ "octstr": { "hex": info.encryptionSchemeIV } }
								]
							}
						]
					}
				]
			},
			{ "octstr": { "hex": info.ciphertext } }
		]
	});
	return asn1Obj.getEncodedHex();
}

/** @typedef {{
	ciphertext: string,
	pbkdf2Salt: string,
	pbkdf2Iter: number,
	encryptionSchemeAlg: string,
	encryptionSchemeIV: string
}} PKCS8Info */ var PKCS8Info;

/**
 * @param {string} plainKeyHex 
 * @param {string | WordArray} passcode 
 * @returns {PKCS8Info}
 */
function getEencryptedPKCS8Info(plainKeyHex, passcode) {
	let pbkdf2Iter = 100;
	let pbkdf2SaltWS = WordArray.random(8);
	let encryptionSchemeAlg = "DES-EDE3-CBC";
	let encryptionSchemeIVWS = WordArray.random(8);
	// PBKDF2 key
	let pbkdf2KeyWS = PBKDF2(passcode,
		pbkdf2SaltWS, {
		"keySize": 192 / 32,
		"iterations": pbkdf2Iter
	});
	// ENCRYPT
	let plainKeyWS = Hex.parse(plainKeyHex);
	let encryptedKeyHex =
		TripleDES.encrypt(plainKeyWS, pbkdf2KeyWS, { "iv": encryptionSchemeIVWS }) + "";

	//alert("encryptedKeyHex=" + encryptedKeyHex);

	//alert("info.ciphertext=" + info.ciphertext);
	return {
		ciphertext: encryptedKeyHex,
		pbkdf2Salt: Hex.stringify(pbkdf2SaltWS),
		pbkdf2Iter: pbkdf2Iter,
		encryptionSchemeAlg: encryptionSchemeAlg,
		encryptionSchemeIV: Hex.stringify(encryptionSchemeIVWS)
	}
}

/**
 * get PEM formatted private or public key file from a RSA/ECDSA/DSA key object
 * @param {KeyObject | string} keyObjOrHex key object {@link RSAKeyEx}, {@link ECDSA} or {@link DSA} to encode to
 * @param {string=} formatType (OPTION) output format type of "PKCS1PRV", "PKCS5PRV" or "PKCS8PRV" for private key
 * @param {string=} passwd (OPTION) password to protect private key
 * @param {string=} encAlg (OPTION) encryption algorithm for PKCS#5. currently supports DES-CBC, DES-EDE3-CBC and AES-{128,192,256}-CBC
 * @param {string=} hexType (OPTION) type of hex string (ex. pkcs5prv, pkcs8prv)
 * @param {string=} ivsaltHex hexadecimal string of IV and salt (default generated random IV)
 * @returns {string}
 * @description
 * <dl>
 * <dt><b>NOTE1:</b>
 * <dd>
 * PKCS#5 encrypted private key protection algorithm supports DES-CBC, 
 * DES-EDE3-CBC and AES-{128,192,256}-CBC
 * <dt><b>NOTE2:</b>
 * <dd>
 * OpenSSL supports
 * <dt><b>NOTE3:</b>
 * <dd>
 * Parameter "ivsaltHex" supported since jsrsasign 8.0.0 keyutil 1.2.0.
 * </dl>
 * @example
 * KEUUTIL.getPEM(publicKey) =&gt; generates PEM PKCS#8 public key 
 * KEUUTIL.getPEM(privateKey, "PKCS1PRV") =&gt; generates PEM PKCS#1 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass") =&gt; generates PEM PKCS#5 encrypted private key 
 *                                                          with DES-EDE3-CBC (DEFAULT)
 * KEUUTIL.getPEM(privateKey, "PKCS5PRV", "pass", "DES-CBC") =&gt; generates PEM PKCS#5 encrypted 
 *                                                                 private key with DES-CBC
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV") =&gt; generates PEM PKCS#8 plain private key
 * KEUUTIL.getPEM(privateKey, "PKCS8PRV", "pass") =&gt; generates PEM PKCS#8 encrypted private key
 *                                                      with PBKDF2_HmacSHA1_3DES
 */
export function getPEM(keyObjOrHex, formatType, passwd, encAlg, hexType, ivsaltHex) {
	// 1. public key

	// x. PEM PKCS#8 public key of RSA/ECDSA/DSA public key object
	if (((RSAKeyEx !== undefined && keyObjOrHex instanceof RSAKeyEx) ||
		(DSA !== undefined && keyObjOrHex instanceof DSA) ||
		(ECDSA !== undefined && keyObjOrHex instanceof ECDSA)) &&
		keyObjOrHex.isPublic == true &&
		(formatType === undefined || formatType == "PKCS8PUB")) {
		let asn1Obj = new SubjectPublicKeyInfo(keyObjOrHex);
		let asn1Hex = asn1Obj.getEncodedHex();
		return hextopem(asn1Hex, "PUBLIC KEY");
	}

	// 2. private

	// x. PEM PKCS#1 plain private key of RSA private key object
	if (formatType == "PKCS1PRV" &&
		RSAKeyEx !== undefined &&
		keyObjOrHex instanceof RSAKeyEx &&
		(passwd === undefined || passwd == null) &&
		keyObjOrHex.isPrivate == true) {

		let asn1Obj = rsaprv2asn1obj(keyObjOrHex);
		let asn1Hex = asn1Obj.getEncodedHex();
		return hextopem(asn1Hex, "RSA PRIVATE KEY");
	}

	// x. PEM PKCS#1 plain private key of ECDSA private key object
	if (formatType == "PKCS1PRV" &&
		ECDSA !== undefined &&
		keyObjOrHex instanceof ECDSA &&
		(passwd === undefined || passwd == null) &&
		keyObjOrHex.isPrivate == true) {

		let asn1Obj1 =
			new DERObjectIdentifier({ 'name': keyObjOrHex.curveName });
		let asn1Hex1 = asn1Obj1.getEncodedHex();
		let asn1Obj2 = ecdsaprv2asn1obj(keyObjOrHex);
		let asn1Hex2 = asn1Obj2.getEncodedHex();

		let s = "";
		s += hextopem(asn1Hex1, "EC PARAMETERS");
		s += hextopem(asn1Hex2, "EC PRIVATE KEY");
		return s;
	}

	// x. PEM PKCS#1 plain private key of DSA private key object
	if (formatType == "PKCS1PRV" &&
		DSA !== undefined &&
		keyObjOrHex instanceof DSA &&
		(passwd === undefined || passwd == null) &&
		keyObjOrHex.isPrivate == true) {

		let asn1Obj = dsaprv2asn1obj(keyObjOrHex);
		let asn1Hex = asn1Obj.getEncodedHex();
		return hextopem(asn1Hex, "DSA PRIVATE KEY");
	}

	// 3. private

	// x. PEM PKCS#5 encrypted private key of RSA private key object
	if (formatType == "PKCS5PRV" &&
		RSAKeyEx !== undefined &&
		keyObjOrHex instanceof RSAKeyEx &&
		(passwd !== undefined && passwd != null) &&
		keyObjOrHex.isPrivate == true) {

		let asn1Obj = rsaprv2asn1obj(keyObjOrHex);
		let asn1Hex = asn1Obj.getEncodedHex();

		if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
		return getEncryptedPKCS5PEMFromPrvKeyHex("RSA", asn1Hex, passwd, encAlg, ivsaltHex);
	}

	// x. PEM PKCS#5 encrypted private key of ECDSA private key object
	if (formatType == "PKCS5PRV" &&
		ECDSA !== undefined &&
		keyObjOrHex instanceof ECDSA &&
		(passwd !== undefined && passwd != null) &&
		keyObjOrHex.isPrivate == true) {

		let asn1Obj = ecdsaprv2asn1obj(keyObjOrHex);
		let asn1Hex = asn1Obj.getEncodedHex();

		if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
		return getEncryptedPKCS5PEMFromPrvKeyHex("EC", asn1Hex, passwd, encAlg, ivsaltHex);
	}

	// x. PEM PKCS#5 encrypted private key of DSA private key object
	if (formatType == "PKCS5PRV" &&
		DSA !== undefined &&
		keyObjOrHex instanceof DSA &&
		(passwd !== undefined && passwd != null) &&
		keyObjOrHex.isPrivate == true) {

		let asn1Obj = dsaprv2asn1obj(keyObjOrHex);
		let asn1Hex = asn1Obj.getEncodedHex();

		if (encAlg === undefined) encAlg = "DES-EDE3-CBC";
		return getEncryptedPKCS5PEMFromPrvKeyHex("DSA", asn1Hex, passwd, encAlg, ivsaltHex);
	}

	// x. PEM PKCS#8 plain private key of RSA private key object
	if (formatType == "PKCS8PRV" &&
		RSAKeyEx != undefined &&
		keyObjOrHex instanceof RSAKeyEx &&
		keyObjOrHex.isPrivate == true) {

		let keyObj = rsaprv2asn1obj(keyObjOrHex);
		let keyHex = keyObj.getEncodedHex();

		let asn1Obj = newObject({
			"seq": [
				{ "int": 0 },
				{ "seq": [{ "oid": { "name": "rsaEncryption" } }, { "null": true }] },
				{ "octstr": { "hex": keyHex } }
			]
		});
		let asn1Hex = asn1Obj.getEncodedHex();

		if (passwd === undefined || passwd == null) {
			return hextopem(asn1Hex, "PRIVATE KEY");
		} else {
			let asn1Hex2 = getEncryptedPKCS8(asn1Hex, passwd);
			return hextopem(asn1Hex2, "ENCRYPTED PRIVATE KEY");
		}
	}

	// x. PEM PKCS#8 plain private key of ECDSA private key object
	if (formatType == "PKCS8PRV" &&
		ECDSA !== undefined &&
		keyObjOrHex instanceof ECDSA &&
		keyObjOrHex.isPrivate == true) {

		let keyObj = newObject({
			"seq": [
				{ "int": 1 },
				{ "octstr": { "hex": keyObjOrHex.prvKeyHex } },
				{ "tag": ['a1', true, { "bitstr": { "hex": "00" + keyObjOrHex.pubKeyHex } }] }
			]
		});
		let keyHex = keyObj.getEncodedHex();

		let asn1Obj = newObject({
			"seq": [
				{ "int": 0 },
				{
					"seq": [
						{ "oid": { "name": "ecPublicKey" } },
						{ "oid": { "name": keyObjOrHex.curveName } }
					]
				},
				{ "octstr": { "hex": keyHex } }
			]
		});

		let asn1Hex = asn1Obj.getEncodedHex();
		if (passwd === undefined || passwd == null) {
			return hextopem(asn1Hex, "PRIVATE KEY");
		} else {
			let asn1Hex2 = getEncryptedPKCS8(asn1Hex, passwd);
			return hextopem(asn1Hex2, "ENCRYPTED PRIVATE KEY");
		}
	}

	// x. PEM PKCS#8 plain private key of DSA private key object
	if (formatType == "PKCS8PRV" &&
		DSA !== undefined &&
		keyObjOrHex instanceof DSA &&
		keyObjOrHex.isPrivate == true) {

		let keyObj = new DERInteger({ 'bigint': keyObjOrHex.x });
		let keyHex = keyObj.getEncodedHex();

		let asn1Obj = newObject({
			"seq": [
				{ "int": 0 },
				{
					"seq": [
						{ "oid": { "name": "dsa" } },
						{
							"seq": [
								{ "int": { "bigint": keyObjOrHex.p } },
								{ "int": { "bigint": keyObjOrHex.q } },
								{ "int": { "bigint": keyObjOrHex.g } }
							]
						}
					]
				},
				{ "octstr": { "hex": keyHex } }
			]
		});

		let asn1Hex = asn1Obj.getEncodedHex();
		if (passwd === undefined || passwd == null) {
			return hextopem(asn1Hex, "PRIVATE KEY");
		} else {
			let asn1Hex2 = getEncryptedPKCS8(asn1Hex, passwd);
			return hextopem(asn1Hex2, "ENCRYPTED PRIVATE KEY");
		}
	}

	throw "unsupported object nor format";
}

// -- PUBLIC METHODS FOR CSR --------------------------------------------------

/** @typedef {{
	p8pubkeyhex: string
}} CSRHex */ var CSRHex

/**
 * get RSAKeyEx/DSA/ECDSA public key object from PEM formatted PKCS#10 CSR string
 * @param {string} csrPEM PEM formatted PKCS#10 CSR string
 * @return {KeyObject} RSAKeyEx/DSA/ECDSA public key object
 */
export function getKeyFromCSRPEM(csrPEM) {
	let csrHex = pemtohex(csrPEM, "CERTIFICATE REQUEST");
	let key = getKeyFromCSRHex(csrHex);
	return key;
}

/**
 * get RSAKeyEx/DSA/ECDSA public key object from hexadecimal string of PKCS#10 CSR
 * @param {string} csrHex hexadecimal string of PKCS#10 CSR
 * @return {KeyObject} RSAKeyEx/DSA/ECDSA public key object
 */
export function getKeyFromCSRHex(csrHex) {
	let info = parseCSRHex(csrHex);
	let key = getKey(info.p8pubkeyhex, null, "pkcs8pub");
	return key;
}

/**
 * parse hexadecimal string of PKCS#10 CSR (certificate signing request)
 * @param {string} csrHex hexadecimal string of PKCS#10 CSR
 * @return {CSRHex} associative array of parsed CSR
 * @description
 * Resulted associative array has following properties:
 * <ul>
 * <li>p8pubkeyhex - hexadecimal string of subject public key in PKCS#8</li>
 * </ul>
 */
export function parseCSRHex(csrHex) {
	let h = csrHex;

	// 1. sequence
	if (h.substr(0, 2) != "30")
		throw "malformed CSR(code:001)"; // not sequence

	let a1 = getChildIdx(h, 0);
	if (a1.length < 1)
		throw "malformed CSR(code:002)"; // short length

	// 2. 2nd sequence
	if (h.substr(a1[0], 2) != "30")
		throw "malformed CSR(code:003)"; // not sequence

	let a2 = getChildIdx(h, a1[0]);
	if (a2.length < 3)
		throw "malformed CSR(code:004)"; // 2nd seq short elem

	return {
		p8pubkeyhex: getTLV(h, a2[2])
	}
}

// -- OTHER STATIC PUBLIC METHODS  -------------------------------------------------

/**
 * convert from RSAKeyEx/ECDSA public/private key object to RFC 7517 JSON Web Key(JWK)
 * @param {RSAKeyEx | ECDSA} keyObj RSAKeyEx/ECDSA public/private key object
 * @return {Object<string,*>} JWK object
 * @description
 * This static method convert from RSAKeyEx/ECDSA public/private key object 
 * to RFC 7517 JSON Web Key(JWK)
 * @example
 * kp1 = generateKeypair("EC", "P-256");
 * jwkPrv1 = getJWKFromKey(kp1.prvKeyObj);
 * jwkPub1 = getJWKFromKey(kp1.pubKeyObj);
 *
 * kp2 = generateKeypair("RSA", 2048);
 * jwkPrv2 = getJWKFromKey(kp2.prvKeyObj);
 * jwkPub2 = getJWKFromKey(kp2.pubKeyObj);
 *
 * // if you need RFC 7638 JWK thumprint as kid do like this:
 * jwkPub2.kid = KJUR.jws.JWS.getJWKthumbprint(jwkPub2);
 */
export function getJWKFromKey(keyObj) {
	/** @dict */
	let jwk = {};
	if (keyObj instanceof RSAKeyEx && keyObj.isPrivate) {
		jwk['kty'] = "RSA";
		jwk['n'] = hextob64u(keyObj.n.toString(16));
		jwk['e'] = hextob64u(keyObj.e.toString(16));
		jwk['d'] = hextob64u(keyObj.d.toString(16));
		jwk['p'] = hextob64u(keyObj.p.toString(16));
		jwk['q'] = hextob64u(keyObj.q.toString(16));
		jwk['dp'] = hextob64u(keyObj.dmp1.toString(16));
		jwk['dq'] = hextob64u(keyObj.dmq1.toString(16));
		jwk['qi'] = hextob64u(keyObj.coeff.toString(16));
		return jwk;
	} else if (keyObj instanceof RSAKeyEx && keyObj.isPublic) {
		jwk['kty'] = "RSA";
		jwk['n'] = hextob64u(keyObj.n.toString(16));
		jwk['e'] = hextob64u(keyObj.e.toString(16));
		return jwk;
	} else if (keyObj instanceof ECDSA && keyObj.isPrivate) {
		let name = keyObj.getShortNISTPCurveName();
		if (name !== "P-256" && name !== "P-384")
			throw "unsupported curve name for JWT: " + name;
		let xy = keyObj.getPublicKeyXYHex();
		jwk['kty'] = "EC";
		jwk['crv'] = name;
		jwk['x'] = hextob64u(xy.x);
		jwk['y'] = hextob64u(xy.y);
		jwk['d'] = hextob64u(keyObj.prvKeyHex);
		return jwk;
	} else if (keyObj instanceof ECDSA && keyObj.isPublic) {
		let name = keyObj.getShortNISTPCurveName();
		if (name !== "P-256" && name !== "P-384")
			throw "unsupported curve name for JWT: " + name;
		let xy = keyObj.getPublicKeyXYHex();
		jwk['kty'] = "EC";
		jwk['crv'] = name;
		jwk['x'] = hextob64u(xy.x);
		jwk['y'] = hextob64u(xy.y);
		return jwk;
	}
	throw "not supported key object";
}
