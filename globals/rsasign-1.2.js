/*
 * rsa-sign.js - adding signing functions to RSAKey class.
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

import { hashString, getPaddedDigestInfoHex, hashHex, DIGESTINFOHEAD } from "./crypto-1.1.js"

/**
 * @fileOverview
 * @name rsasign-1.2.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version jsrsasign 8.0.0 rsasign 1.3.0 (2017-Jun-28)
 * @license <a href="https://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

let _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
    let hashFunc = function(s) { return hashString(s, hashAlg); };
    let sHashHex = hashFunc(s);

    return getPaddedDigestInfoHex(sHashHex, hashAlg, keySize);
}

function _zeroPaddingOfSignature(hex, bitLength) {
    let s = "";
    let nZero = bitLength / 4 - hex.length;
    for (let i = 0; i < nZero; i++) {
	s = s + "0";
    }
    return s + hex;
}

/**
 * sign for a message string with RSA private key.<br/>
 * @param {string} s message string to be signed.
 * @param {string} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
RSAKey.prototype.sign = function(s, hashAlg) {
    let hashFunc = function(s) { return hashString(s, hashAlg); };
    let sHashHex = hashFunc(s);

    return this.signWithMessageHash(sHashHex, hashAlg);
};

/**
 * sign hash value of message to be signed with RSA private key.<br/>
 * @param {string} sHashHex hexadecimal string of hash value of message to be signed.
 * @param {string} hashAlg hash algorithm name for signing.<br/>
 * @return returns hexadecimal string of signature value.
 */
RSAKey.prototype.signWithMessageHash = function(sHashHex, hashAlg) {
    let hPM = getPaddedDigestInfoHex(sHashHex, hashAlg, this.n.bitLength());
    let biPaddedMessage = parseBigInt(hPM, 16);
    let biSign = this.doPrivate(biPaddedMessage);
    let hexSign = biSign.toString(16);
    return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
}

// PKCS#1 (PSS) mask generation function
function pss_mgf1_str(seed, len, hash) {
    let mask = '', i = 0;

    while (mask.length < len) {
        mask += hextorstr(hash(rstrtohex(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]))));
        i += 1;
    }

    return mask;
}

/**
 * sign for a message string with RSA private key by PKCS#1 PSS signing.<br/>
 * @param {string} s message string to be signed.
 * @param {string} hashAlg hash algorithm name for signing.
 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns hexadecimal string of signature value.
 */
RSAKey.prototype.signPSS = function(s, hashAlg, sLen) {
    let hashFunc = function(sHex) { return hashHex(sHex, hashAlg); } 
    let hHash = hashFunc(rstrtohex(s));

    if (sLen === undefined) sLen = -1;
    return this.signWithMessageHashPSS(hHash, hashAlg, sLen);
};

/**
 * sign hash value of message with RSA private key by PKCS#1 PSS signing.<br/>
 * @param {string} hHash hexadecimal hash value of message to be signed.
 * @param {string} hashAlg hash algorithm name for signing.
 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns hexadecimal string of signature value.
 */
RSAKey.prototype.signWithMessageHashPSS = function(hHash, hashAlg, sLen) {
    let mHash = hextorstr(hHash);
    let hLen = mHash.length;
    let emBits = this.n.bitLength() - 1;
    let emLen = Math.ceil(emBits / 8);
    let i;
    let hashFunc = function(sHex) { return hashHex(sHex, hashAlg); } 

    if (sLen === -1 || sLen === undefined) {
        sLen = hLen; // same as hash length
    } else if (sLen === -2) {
        sLen = emLen - hLen - 2; // maximum
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    let salt = '';

    if (sLen > 0) {
        salt = new Array(sLen);
        new SecureRandom().nextBytes(salt);
        salt = String.fromCharCode.apply(String, salt);
    }

    let H = hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt)));
    let PS = [];

    for (i = 0; i < emLen - sLen - hLen - 2; i += 1) {
        PS[i] = 0x00;
    }

    let DB = String.fromCharCode.apply(String, PS) + '\x01' + salt;
    let dbMask = pss_mgf1_str(H, DB.length, hashFunc);
    let maskedDB = [];

    for (i = 0; i < DB.length; i += 1) {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    let mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
    maskedDB[0] &= ~mask;

    for (i = 0; i < hLen; i++) {
        maskedDB.push(H.charCodeAt(i));
    }

    maskedDB.push(0xbc);

    return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(maskedDB)).toString(16),
				   this.n.bitLength());
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
    let rsa = new RSAKey();
    rsa.setPublic(hN, hE);
    let biDecryptedSig = rsa.doPublic(biSig);
    return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
    let biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
    let hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
    for (let algName in DIGESTINFOHEAD) {
	let head = DIGESTINFOHEAD[algName];
	let len = head.length;
	if (hDigestInfo.substring(0, len) == head) {
	    let a = [algName, hDigestInfo.substring(len)];
	    return a;
	}
    }
    return [];
}

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @param {string} sMsg message string to be verified.
 * @param {string} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
RSAKey.prototype.verify = function(sMsg, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
    hSig = hSig.replace(/[ \n]+/g, "");
    let biSig = parseBigInt(hSig, 16);
    if (biSig.bitLength() > this.n.bitLength()) return 0;
    let biDecryptedSig = this.doPublic(biSig);
    let hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    let digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
    if (digestInfoAry.length == 0) return false;
    let algName = digestInfoAry[0];
    let diHashValue = digestInfoAry[1];
    let ff = function(s) { return hashString(s, algName); };
    let msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
};

/**
 * verifies a sigature for a message string with RSA public key.<br/>
 * @param {string} sHashHex hexadecimal hash value of message to be verified.
 * @param {string} hSig hexadecimal string of siganture.<br/>
 *                 non-hexadecimal charactors including new lines will be ignored.
 * @return returns 1 if valid, otherwise 0
 */
RSAKey.prototype.verifyWithMessageHash = function(sHashHex, hSig) {
    hSig = hSig.replace(_RE_HEXDECONLY, '');
    hSig = hSig.replace(/[ \n]+/g, "");
    let biSig = parseBigInt(hSig, 16);
    if (biSig.bitLength() > this.n.bitLength()) return 0;
    let biDecryptedSig = this.doPublic(biSig);
    let hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    let digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
    if (digestInfoAry.length == 0) return false;
    let algName = digestInfoAry[0];
    let diHashValue = digestInfoAry[1];
    return (diHashValue == sHashHex);
};

/**
 * verifies a sigature for a message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @param {string} sMsg message string to be verified.
 * @param {string} hSig hexadecimal string of signature value
 * @param {string} hashAlg hash algorithm name
 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
 * @return returns true if valid, otherwise false
 */
RSAKey.prototype.verifyPSS = function(sMsg, hSig, hashAlg, sLen) {
    let hashFunc = function(sHex) { return hashHex(sHex, hashAlg); };
    let hHash = hashFunc(rstrtohex(sMsg));

    if (sLen === undefined) sLen = -1;
    return this.verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen);
}

/**
 * verifies a sigature for a hash value of message string with RSA public key by PKCS#1 PSS sign.<br/>
 * @param {string} hHash hexadecimal hash value of message string to be verified.
 * @param {string} hSig hexadecimal string of signature value
 * @param {string} hashAlg hash algorithm name
 * @param {number} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
 *        There are two special values:
 *        <ul>
 *        <li>-1: sets the salt length to the digest length</li>
 *        <li>-2: sets the salt length to maximum permissible value
 *           (i.e. keybytelen - hashbytelen - 2)</li>
 *        </ul>
 *        DEFAULT is -1 (NOTE: OpenSSL's default is -2.)
 * @return returns true if valid, otherwise false
 */
RSAKey.prototype.verifyWithMessageHashPSS = function(hHash, hSig, hashAlg, sLen) {
    let biSig = new BigInteger(hSig, 16);

    if (biSig.bitLength() > this.n.bitLength()) {
        return false;
    }

    let hashFunc = function(sHex) { return hashHex(sHex, hashAlg); };
    let mHash = hextorstr(hHash);
    let hLen = mHash.length;
    let emBits = this.n.bitLength() - 1;
    let emLen = Math.ceil(emBits / 8);
    let i;

    if (sLen === -1 || sLen === undefined) {
        sLen = hLen; // same as hash length
    } else if (sLen === -2) {
        sLen = emLen - hLen - 2; // recover
    } else if (sLen < -2) {
        throw "invalid salt length";
    }

    if (emLen < (hLen + sLen + 2)) {
        throw "data too long";
    }

    let em = this.doPublic(biSig).toByteArray();

    for (i = 0; i < em.length; i += 1) {
        em[i] &= 0xff;
    }

    while (em.length < emLen) {
        em.unshift(0);
    }

    if (em[emLen -1] !== 0xbc) {
        throw "encoded message does not end in 0xbc";
    }

    em = String.fromCharCode.apply(String, em);

    let maskedDB = em.substr(0, emLen - hLen - 1);
    let H = em.substr(maskedDB.length, hLen);

    let mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;

    if ((maskedDB.charCodeAt(0) & mask) !== 0) {
        throw "bits beyond keysize not zero";
    }

    let dbMask = pss_mgf1_str(H, maskedDB.length, hashFunc);
    let DB = [];

    for (i = 0; i < maskedDB.length; i += 1) {
        DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    DB[0] &= ~mask;

    let checkLen = emLen - hLen - sLen - 2;

    for (i = 0; i < checkLen; i += 1) {
        if (DB[i] !== 0x00) {
            throw "leftmost octets not zero";
        }
    }

    if (DB[checkLen] !== 0x01) {
        throw "0x01 marker not found";
    }

    return H === hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash +
				     String.fromCharCode.apply(String, DB.slice(-sLen)))));
}

RSAKey.SALT_LEN_HLEN = -1;
RSAKey.SALT_LEN_MAX = -2;
RSAKey.SALT_LEN_RECOVER = -2;

/** * @description Tom Wu's RSA Key class and extension
 */
