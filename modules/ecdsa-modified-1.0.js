/*
 * ecdsa-modified.js - modified Bitcoin.ECDSA class
 * 
 * Original work Copyright (c) 2013-2017 Stefan Thomas (github.com/justmoon), Kenji Urushima (kenji.urushima@gmail.com)
 * Modified work Copyright (c) 2020 Sergei Sovik <sergeisovik@yahoo.com>
 *
 * LICENSE
 *   https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
 */

"use strict";

import { getVbyList, isASN1HEX, getChildIdx, getV } from "./asn1hex-1.1.js"
import { BigInteger } from "./../../js-bn/modules/jsbn.js"
import { ECPointFp } from "./../../js-bn/modules/ec.js"
import { SecureRandom } from "./../../js-bn/modules/rng.js"
import { ECParams, getByName } from "./ecparam-1.0.js"
import { DERInteger, DERSequence } from "./asn1-1.0.js"
import { Dictionary, isArray } from "./../../../include/type.js"

/** @typedef {{
	x: string,
	y: string
}} XYHex */ var XYHex;

/** @typedef {{
	ecprvhex: string,
	ecpubhex: string
}} KeyPairHex */ export var KeyPairHex;

/** @typedef {{
	r: string,
	s: string
}} SigHex */ var SigHex;

/** @typedef {{
 r: BigInteger,
 s: BigInteger
}} Sig */ var Sig;

/** @typedef {{
 r: BigInteger,
 s: BigInteger,
 i: number
}} SigCompact */ var SigCompact;

const rng = new SecureRandom();

/**
 * class for EC key generation, ECDSA signing and verifcation
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class except
 * for generating an EC key pair. Please use {@link Signature} class instead.
 * </p>
 * <p>
 * This class was originally developped by Stefan Thomas for Bitcoin JavaScript library.
 * (See {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/ecdsa.js})
 * Currently this class supports following named curves and their aliases.
 * <ul>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
 * </ul>
 * </p>
 */
export class ECDSA {
	/**
	 * @param {Dictionary=} params 
	 */
	constructor(params) {
		/** @type {string | null} */ this.curveName = "secp256r1";	// curve name default
		/** @type {ECParams | null} */ this.ecparams = null;
		/** @type {string | null} */ this.prvKeyHex = null;
		/** @type {string | null} */ this.pubKeyHex = null;

		/** @type {BigInteger | null} */ this.P_OVER_FOUR = null;

		this.type = "EC";
		this.isPrivate = false;
		this.isPublic = false;

		if (params !== undefined) {
			if (params['curve'] !== undefined) {
				this.curveName = String(params['curve']);
			}
		}
		this.setNamedCurve(this.curveName);
		if (params !== undefined) {
			if (params['prv'] !== undefined) this.setPrivateKeyHex(params['prv']);
			if (params['pub'] !== undefined) this.setPublicKeyHex(params['pub']);
		}
	}

	/**
	 * @private
	 * @param {ECPointFp} P 
	 * @param {BigInteger} k 
	 * @param {ECPointFp} Q 
	 * @param {BigInteger} l 
	 * @returns {ECPointFp}
	 */
	implShamirsTrick(P, k, Q, l) {
		let m = Math.max(k.bitLength(), l.bitLength());
		let Z = P.add2D(Q);
		let R = P.curve.getInfinity();

		for (let i = m - 1; i >= 0; --i) {
			R = R.twice2D();

			R.z = BigInteger.ONE();

			if (k.testBit(i)) {
				if (l.testBit(i)) {
					R = R.add2D(Z);
				} else {
					R = R.add2D(P);
				}
			} else {
				if (l.testBit(i)) {
					R = R.add2D(Q);
				}
			}
		}

		return R;
	}

	/**
	 * @param {BigInteger} limit 
	 */
	getBigRandom(limit) {
		return new BigInteger(limit.bitLength(), rng)
			.mod(limit.subtract(BigInteger.ONE()))
			.add(BigInteger.ONE());
	}

	/**
	 * @param {string} curveName 
	 */
	setNamedCurve(curveName) {
		this.ecparams = getByName(curveName);
		this.prvKeyHex = null;
		this.pubKeyHex = null;
		this.curveName = curveName;
	}

	/**
	 * @param {string} prvKeyHex 
	 */
	setPrivateKeyHex(prvKeyHex) {
		this.isPrivate = true;
		this.prvKeyHex = prvKeyHex;
	}

	/**
	 * @param {string} pubKeyHex 
	 */
	setPublicKeyHex(pubKeyHex) {
		this.isPublic = true;
		this.pubKeyHex = pubKeyHex;
	}

    /**
     * get X and Y hexadecimal string value of public key
     * @return {XYHex} associative array of x and y value of public key
     * @example
     * ec = new ECDSA({'curve': 'secp256r1', 'pub': pubHex});
     * ec.getPublicKeyXYHex() &rarr; { x: '01bacf...', y: 'c3bc22...' }
     */
	getPublicKeyXYHex() {
		let h = this.pubKeyHex;
		if (h.substr(0, 2) !== "04")
			throw "this method supports uncompressed format(04) only";

		let charlen = this.ecparams.keylen / 4;
		if (h.length !== 2 + charlen * 2)
			throw "malformed public key hex length";

		return {
			x: h.substr(2, charlen),
			y: h.substr(2 + charlen)
		}
	}

    /**
     * get NIST curve short name such as "P-256" or "P-384"
     * @return {string | null} short NIST P curve name such as "P-256" or "P-384" if it's NIST P curve otherwise null;
     * @example
     * ec = new ECDSA({'curve': 'secp256r1', 'pub': pubHex});
     * ec.getShortPCurveName() &rarr; "P-256";
     */
	getShortNISTPCurveName() {
		let s = this.curveName;
		if (s === "secp256r1" || s === "NIST P-256" ||
			s === "P-256" || s === "prime256v1")
			return "P-256";
		if (s === "secp384r1" || s === "NIST P-384" || s === "P-384")
			return "P-384";
		return null;
	}

    /**
     * generate a EC key pair
     * @return {KeyPairHex} associative array of hexadecimal string of private and public key
     * @example
     * let ec = new ECDSA({'curve': 'secp256r1'});
     * let keypair = ec.generateKeyPairHex();
     * let pubhex = keypair.ecpubhex; // hexadecimal string of EC public key
     * let prvhex = keypair.ecprvhex; // hexadecimal string of EC private key (=d)
     */
	generateKeyPairHex() {
		let biN = this.ecparams.n;
		let biPrv = this.getBigRandom(biN);
		let epPub = this.ecparams.G.multiply(biPrv);
		let biX = epPub.getX().toBigInteger();
		let biY = epPub.getY().toBigInteger();

		let charlen = this.ecparams.keylen / 4;
		let hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
		let hX = ("0000000000" + biX.toString(16)).slice(- charlen);
		let hY = ("0000000000" + biY.toString(16)).slice(- charlen);
		let hPub = "04" + hX + hY;

		this.setPrivateKeyHex(hPrv);
		this.setPublicKeyHex(hPub);
		return { ecprvhex: hPrv, ecpubhex: hPub };
	}

	/**
	 * @param {string} hashHex 
	 * @returns {string | null}
	 */
	signWithMessageHash(hashHex) {
		if (this.prvKeyHex === null)
			return null;
		return this.signHex(hashHex, this.prvKeyHex);
	}

    /**
     * signing to message hash
     * @param {string} hashHex hexadecimal string of hash value of signing message
     * @param {string} privHex hexadecimal string of EC private key
     * @return {string} hexadecimal string of ECDSA signature
     * @example
     * let ec = new ECDSA({'curve': 'secp256r1'});
     * let sigValue = ec.signHex(hash, prvKey);
     */
	signHex(hashHex, privHex) {
		let d = new BigInteger(privHex, 16);
		let n = this.ecparams.n;
		let e = new BigInteger(hashHex, 16);

		/** @type {BigInteger} */ let r;
		/** @type {BigInteger} */ let k;
		do {
			k = this.getBigRandom(n);
			let G = this.ecparams.G;
			let Q = G.multiply(k);
			r = Q.getX().toBigInteger().mod(n);
		} while (r.compareTo(BigInteger.ZERO()) <= 0);

		let s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

		return ECDSA.biRSSigToASN1Sig(r, s);
	}

	/**
	 * @param {Array<number>} hash 
	 * @param {BigInteger} priv 
	 */
	sign(hash, priv) {
		let d = priv;
		let n = this.ecparams.n;
		let e = new BigInteger(hash, 256); //BigInteger.fromByteArrayUnsigned(hash);

		/** @type {BigInteger} */ let k;
		/** @type {BigInteger} */ let r;
		do {
			k = this.getBigRandom(n);
			let G = this.ecparams.G;
			let Q = G.multiply(k);
			r = Q.getX().toBigInteger().mod(n);
		} while (r.compareTo(BigInteger.ZERO()) <= 0);

		let s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
		return this.serializeSig(r, s);
	}

	/**
	 * @param {string} hashHex 
	 * @param {string} sigHex 
	 * @returns {boolean | null}
	 */
	verifyWithMessageHash(hashHex, sigHex) {
		if (this.pubKeyHex === null)
			return null;
		return this.verifyHex(hashHex, sigHex, this.pubKeyHex);
	}

    /**
     * verifying signature with message hash and public key
     * @param {string} hashHex hexadecimal string of hash value of signing message
     * @param {string} sigHex hexadecimal string of signature value
     * @param {string} pubkeyHex hexadecimal string of public key
     * @return {boolean} true if the signature is valid, otherwise false
     * @example
     * let ec = new ECDSA({'curve': 'secp256r1'});
     * let result = ec.verifyHex(msgHashHex, sigHex, pubkeyHex);
     */
	verifyHex(hashHex, sigHex, pubkeyHex) {
		let r, s;

		let obj = ECDSA.parseSigHex(sigHex);
		r = obj.r;
		s = obj.s;

		let Q = ECPointFp.decodeFromHex(this.ecparams.curve, pubkeyHex);
		let e = new BigInteger(hashHex, 16);

		return this.verifyRaw(e, r, s, Q);
	}

	/**
	 * @param {Array<number>} hash 
	 * @param {Sig | Array<number>} sig 
	 * @param {ECPointFp | Array<number>} pubkey 
	 * @returns {boolean}
	 */
	verify(hash, sig, pubkey) {
		let r, s;
		if (isArray(sig)) {
			let obj = this.parseSig(/** @type {Array<number>} */ ( sig ));
			r = obj.r;
			s = obj.s;
		} else if ("object" === typeof sig && sig.r && sig.s) {
			r = sig.r;
			s = sig.s;
		} else {
			throw "Invalid value for signature";
		}

		let Q;
		if (pubkey instanceof ECPointFp) {
			Q = pubkey;
		} else if (isArray(pubkey)) {
			Q = ECPointFp.decodeFrom(this.ecparams.curve, pubkey);
		} else {
			throw "Invalid format for pubkey value, must be byte array or ECPointFp";
		}
		let e = new BigInteger(hash, 256); //BigInteger.fromByteArrayUnsigned(hash);

		return this.verifyRaw(e, r, s, Q);
	}

	/**
	 * @param {BigInteger} e 
	 * @param {BigInteger} r 
	 * @param {BigInteger} s 
	 * @param {ECPointFp} Q 
	 * @returns {boolean}
	 */
	verifyRaw(e, r, s, Q) {
		let n = this.ecparams.n;
		let G = this.ecparams.G;

		if (r.compareTo(BigInteger.ONE()) < 0 ||
			r.compareTo(n) >= 0)
			return false;

		if (s.compareTo(BigInteger.ONE()) < 0 ||
			s.compareTo(n) >= 0)
			return false;

		let c = s.modInverse(n);

		let u1 = e.multiply(c).mod(n);
		let u2 = r.multiply(c).mod(n);

		// TODO(!!!): For some reason Shamir's trick isn't working with
		// signed message verification!? Probably an implementation
		// error!
		//let point = implShamirsTrick(G, u1, Q, u2);
		let point = G.multiply(u1).add(Q.multiply(u2));

		let v = point.getX().toBigInteger().mod(n);

		return v.equals(r);
	}

    /**
     * Serialize a signature into DER format.
     *
     * Takes two BigIntegers representing r and s and returns a byte array.
	 * 
	 * @param {BigInteger} r
	 * @param {BigInteger} s
	 * @returns {Array<number>}
     */
	serializeSig(r, s) {
		let rBa = r.toByteArray(); //r.toByteArraySigned();
		let sBa = s.toByteArray(); //s.toByteArraySigned();

		/** @type {Array<number>} */ let sequence = [];
		sequence.push(0x02); // INTEGER
		sequence.push(rBa.length);
		sequence = sequence.concat(rBa);

		sequence.push(0x02); // INTEGER
		sequence.push(sBa.length);
		sequence = sequence.concat(sBa);

		sequence.unshift(sequence.length);
		sequence.unshift(0x30); // SEQUENCE
		return sequence;
	}

    /**
     * Parses a byte array containing a DER-encoded signature.
     *
     * This function will return an object of the form:
     *
     * {
     *   r: BigInteger,
     *   s: BigInteger
     * }
	 * 
	 * @param {Array<number>} sig
	 * @returns {Sig}
     */
	parseSig(sig) {
		let cursor;
		if (sig[0] != 0x30)
			throw new Error("Signature not a valid DERSequence");

		cursor = 2;
		if (sig[cursor] != 0x02)
			throw new Error("First element in signature must be a DERInteger");;
		let rBa = sig.slice(cursor + 2, cursor + 2 + sig[cursor + 1]);

		cursor += 2 + sig[cursor + 1];
		if (sig[cursor] != 0x02)
			throw new Error("Second element in signature must be a DERInteger");
		let sBa = sig.slice(cursor + 2, cursor + 2 + sig[cursor + 1]);

		cursor += 2 + sig[cursor + 1];

		//if (cursor != sig.length)
		//  throw new Error("Extra bytes in signature");

		let r = new BigInteger(rBa, 256); //BigInteger.fromByteArrayUnsigned(rBa);
		let s = new BigInteger(sBa, 256); //BigInteger.fromByteArrayUnsigned(sBa);

		return { r: r, s: s };
	}

	/**
	 * @param {Array<number>} sig
	 * @returns {SigCompact}
	 */
	parseSigCompact(sig) {
		if (sig.length !== 65) {
			throw "Signature has the wrong length";
		}

		// Signature is prefixed with a type byte storing three bits of
		// information.
		let i = sig[0] - 27;
		if (i < 0 || i > 7) {
			throw "Invalid signature type";
		}

		let n = this.ecparams.n;
		let r = new BigInteger(sig.slice(1, 33)).mod(n); //BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
		let s = new BigInteger(sig.slice(33, 65)).mod(n); //BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

		return { r: r, s: s, i: i };
	}

    /**
     * read an ASN.1 hexadecimal string of PKCS#1/5 plain ECC private key<br/>
     * @param {string} h hexadecimal string of PKCS#1/5 ECC private key
     */
	readPKCS5PrvKeyHex(h) {
		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		/** @type {string} */ let hCurve;
		/** @type {string} */ let hPrv;
		/** @type {string} */ let hPub;
		try {
			hCurve = getVbyList(h, 0, [2, 0], "06");
			hPrv = getVbyList(h, 0, [1], "04");
			try {
				hPub = getVbyList(h, 0, [3, 0], "03").substr(2);
			} catch (ex) { };
		} catch (ex) {
			throw "malformed PKCS#1/5 plain ECC private key";
		}

		this.curveName = ECDSA.getName(hCurve);
		if (this.curveName === null) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
		this.setPrivateKeyHex(hPrv);
		this.isPublic = false;
	}

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 plain ECC private key<br/>
     * @param {string} h hexadecimal string of PKCS#8 ECC private key
     */
	readPKCS8PrvKeyHex(h) {
		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		/** @type {string} */ let hECOID;
		/** @type {string} */ let hCurve;
		/** @type {string} */ let hPrv;
		/** @type {string} */ let hPub;
		try {
			hECOID = getVbyList(h, 0, [1, 0], "06");
			hCurve = getVbyList(h, 0, [1, 1], "06");
			hPrv = getVbyList(h, 0, [2, 0, 1], "04");
			try {
				hPub = getVbyList(h, 0, [2, 0, 2, 0], "03").substr(2);
			} catch (ex) { };
		} catch (ex) {
			throw "malformed PKCS#8 plain ECC private key";
		}

		this.curveName = ECDSA.getName(hCurve);
		if (this.curveName === null) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
		this.setPrivateKeyHex(hPrv);
		this.isPublic = false;
	}

    /**
     * read an ASN.1 hexadecimal string of PKCS#8 ECC public key<br/>
     * @param {string} h hexadecimal string of PKCS#8 ECC public key
     */
	readPKCS8PubKeyHex(h) {
		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		/** @type {string} */ let hECOID;
		/** @type {string} */ let hCurve;
		/** @type {string} */ let hPub;
		try {
			hECOID = getVbyList(h, 0, [0, 0], "06");
			hCurve = getVbyList(h, 0, [0, 1], "06");
			hPub = getVbyList(h, 0, [1], "03").substr(2);
		} catch (ex) {
			throw "malformed PKCS#8 ECC public key";
		}

		this.curveName = ECDSA.getName(hCurve);
		if (this.curveName === null) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
	}

    /**
     * read an ASN.1 hexadecimal string of X.509 ECC public key certificate<br/>
     * @param {string} h hexadecimal string of X.509 ECC public key certificate
     * @param {number} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
     */
	readCertPubKeyHex(h, nthPKI) {
		if (nthPKI !== 5) nthPKI = 6;

		if (isASN1HEX(h) === false)
			throw "not ASN.1 hex string";

		/** @type {string} */ let hCurve;
		/** @type {string} */ let hPub;
		try {
			hCurve = getVbyList(h, 0, [0, nthPKI, 0, 1], "06");
			hPub = getVbyList(h, 0, [0, nthPKI, 1], "03").substr(2);
		} catch (ex) {
			throw "malformed X.509 certificate ECC public key";
		}

		this.curveName = ECDSA.getName(hCurve);
		if (this.curveName === null) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
	}

    /*
     * Recover a public key from a signature.
     *
     * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
     * Key Recovery Operation".
     *
     * http://www.secg.org/download/aid-780/sec1-v2.pdf
     */
    /*
    recoverPubKey: function (r, s, hash, i) {
	// The recovery parameter i has two bits.
	i = i & 3;

	// The less significant bit specifies whether the y coordinate
	// of the compressed point is even or not.
	let isYEven = i & 1;

	// The more significant bit specifies whether we should use the
	// first or second candidate key.
	let isSecondKey = i >> 1;

	let n = this.ecparams.n;
	let G = this.ecparams.G;
	let curve = this.ecparams.curve;
	let p = curve.getQ();
	let a = curve.getA().toBigInteger();
	let b = curve.getB().toBigInteger();

	// We precalculate (p + 1) / 4 where p is if the field order
	if (!P_OVER_FOUR) {
	    P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
	}

	// 1.1 Compute x
	let x = isSecondKey ? r.add(n) : r;

	// 1.3 Convert x to point
	let alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
	let beta = alpha.modPow(P_OVER_FOUR, p);

	let xorOdd = beta.isEven() ? (i % 2) : ((i+1) % 2);
	// If beta is even, but y isn't or vice versa, then convert it,
	// otherwise we're done and y == beta.
	let y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);

	// 1.4 Check that nR is at infinity
	let R = new ECPointFp(curve,
			      curve.fromBigInteger(x),
			      curve.fromBigInteger(y));
	R.validate();

	// 1.5 Compute e from M
	let e = BigInteger.fromByteArrayUnsigned(hash);
	let eNeg = BigInteger.ZERO.subtract(e).mod(n);

	// 1.6 Compute Q = r^-1 (sR - eG)
	let rInv = r.modInverse(n);
	let Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);

	Q.validate();
	if (!this.verifyRaw(e, r, s, Q)) {
	    throw "Pubkey recovery unsuccessful";
	}

	let pubKey = new Bitcoin.ECKey();
	pubKey.pub = Q;
	return pubKey;
    },
    */

    /*
     * Calculate pubkey extraction parameter.
     *
     * When extracting a pubkey from a signature, we have to
     * distinguish four different cases. Rather than putting this
     * burden on the verifier, Bitcoin includes a 2-bit value with the
     * signature.
     *
     * This function simply tries all four cases and returns the value
     * that resulted in a successful pubkey recovery.
     */
    /*
    calcPubkeyRecoveryParam: function (address, r, s, hash) {
	for (let i = 0; i < 4; i++) {
	    try {
		let pubkey = Bitcoin.ECDSA.recoverPubKey(r, s, hash, i);
		if (pubkey.getBitcoinAddress().toString() == address) {
		    return i;
		}
	    } catch (e) {}
	}
	throw "Unable to find valid recovery factor";
    }
    */

	/**
	 * parse ASN.1 DER encoded ECDSA signature
	 * @param {string} sigHex hexadecimal string of ECDSA signature value
	 * @return {Sig} associative array of signature field r and s of BigInteger
	 * @example
	 * let ec = new ECDSA({'curve': 'secp256r1'});
	 * let sig = ec.parseSigHex('30...');
	 * let biR = sig.r; // BigInteger object for 'r' field of signature.
	 * let biS = sig.s; // BigInteger object for 's' field of signature.
	 */
	static parseSigHex(sigHex) {
		let p = ECDSA.parseSigHexInHexRS(sigHex);
		let biR = new BigInteger(p.r, 16);
		let biS = new BigInteger(p.s, 16);

		return { r: biR, s: biS };
	}

	/**
	 * parse ASN.1 DER encoded ECDSA signature
	 * @param {string} sigHex hexadecimal string of ECDSA signature value
	 * @return {SigHex} associative array of signature field r and s in hexadecimal
	 * @example
	 * let ec = new ECDSA({'curve': 'secp256r1'});
	 * let sig = ec.parseSigHexInHexRS('30...');
	 * let hR = sig.r; // hexadecimal string for 'r' field of signature.
	 * let hS = sig.s; // hexadecimal string for 's' field of signature.
	 */
	static parseSigHexInHexRS(sigHex) {
		// 1. ASN.1 Sequence Check
		if (sigHex.substr(0, 2) != "30")
			throw "signature is not a ASN.1 sequence";

		// 2. Items of ASN.1 Sequence Check
		let a = getChildIdx(sigHex, 0);
		if (a.length != 2)
			throw "number of signature ASN.1 sequence elements seem wrong";

		// 3. Integer check
		let iTLV1 = a[0];
		let iTLV2 = a[1];
		if (sigHex.substr(iTLV1, 2) != "02")
			throw "1st item of sequene of signature is not ASN.1 integer";
		if (sigHex.substr(iTLV2, 2) != "02")
			throw "2nd item of sequene of signature is not ASN.1 integer";

		// 4. getting value
		let hR = getV(sigHex, iTLV1);
		let hS = getV(sigHex, iTLV2);

		return { r: hR, s: hS };
	}

	/**
	 * convert hexadecimal ASN.1 encoded signature to concatinated signature
	 * @param {string} asn1SigHex hexadecimal string of ASN.1 encoded ECDSA signature value
	 * @return {string} r-s concatinated format of ECDSA signature value
	 */
	static asn1SigToConcatSig(asn1SigHex) {
		let pSig = ECDSA.parseSigHexInHexRS(asn1SigHex);
		let hR = pSig.r;
		let hS = pSig.s;

		// R and S length is assumed multiple of 128bit(32chars in hex).
		// If leading is "00" and modulo of length is 2(chars) then
		// leading "00" is for two's complement and will be removed.
		if (hR.substr(0, 2) == "00" && (hR.length % 32) == 2)
			hR = hR.substr(2);

		if (hS.substr(0, 2) == "00" && (hS.length % 32) == 2)
			hS = hS.substr(2);

		// R and S length is assumed multiple of 128bit(32chars in hex).
		// If missing two chars then it will be padded by "00".
		if ((hR.length % 32) == 30) hR = "00" + hR;
		if ((hS.length % 32) == 30) hS = "00" + hS;

		// If R and S length is not still multiple of 128bit(32 chars),
		// then error
		if (hR.length % 32 != 0)
			throw "unknown ECDSA sig r length error";
		if (hS.length % 32 != 0)
			throw "unknown ECDSA sig s length error";

		return hR + hS;
	}

	/**
	 * convert hexadecimal concatinated signature to ASN.1 encoded signature
	 * @param {string} concatSig r-s concatinated format of ECDSA signature value
	 * @return {string} hexadecimal string of ASN.1 encoded ECDSA signature value
	 */
	static concatSigToASN1Sig(concatSig) {
		if ((((concatSig.length / 2) * 8) % (16 * 8)) != 0)
			throw "unknown ECDSA concatinated r-s sig  length error";

		let hR = concatSig.substr(0, concatSig.length / 2);
		let hS = concatSig.substr(concatSig.length / 2);
		return ECDSA.hexRSSigToASN1Sig(hR, hS);
	}

	/**
	 * convert hexadecimal R and S value of signature to ASN.1 encoded signature
	 * @param {string} hR hexadecimal string of R field of ECDSA signature value
	 * @param {string} hS hexadecimal string of S field of ECDSA signature value
	 * @return {string} hexadecimal string of ASN.1 encoded ECDSA signature value
	 */
	static hexRSSigToASN1Sig(hR, hS) {
		let biR = new BigInteger(hR, 16);
		let biS = new BigInteger(hS, 16);
		return ECDSA.biRSSigToASN1Sig(biR, biS);
	}

	/**
	 * convert R and S BigInteger object of signature to ASN.1 encoded signature
	 * @param {BigInteger} biR BigInteger object of R field of ECDSA signature value
	 * @param {BigInteger} biS BIgInteger object of S field of ECDSA signature value
	 * @return {string} hexadecimal string of ASN.1 encoded ECDSA signature value
	 */
	static biRSSigToASN1Sig(biR, biS) {
		let derR = new DERInteger(/** @type {Dictionary} */ ( { 'bigint': biR } ));
		let derS = new DERInteger(/** @type {Dictionary} */ ( { 'bigint': biS } ));
		let derSeq = new DERSequence(/** @type {Dictionary} */ ( { 'array': [derR, derS] } ));
		return derSeq.getEncodedHex();
	}

	/**
	 * static method to get normalized EC curve name from curve name or hexadecimal OID value
	 * @param {string} s curve name (ex. P-256) or hexadecimal OID value (ex. 2a86...)
	 * @return {string | null} normalized EC curve name (ex. secp256r1) 
	 * @description
	 * This static method returns normalized EC curve name 
	 * which is supported in jsrsasign
	 * from curve name or hexadecimal OID value.
	 * When curve is not supported in jsrsasign, this method returns null.
	 * Normalized name will be "secp*" in jsrsasign.
	 * @example
	 * ECDSA.getName("2b8104000a") &rarr; "secp256k1"
	 * ECDSA.getName("NIST P-256") &rarr; "secp256r1"
	 * ECDSA.getName("P-521") &rarr; undefined // not supported
	 */
	static getName(s) {
		if (s === "2a8648ce3d030107") return "secp256r1"; // 1.2.840.10045.3.1.7
		if (s === "2b8104000a") return "secp256k1"; // 1.3.132.0.10
		if (s === "2b81040022") return "secp384r1"; // 1.3.132.0.34
		if ("|secp256r1|NIST P-256|P-256|prime256v1|".indexOf(s) !== -1) return "secp256r1";
		if ("|secp256k1|".indexOf(s) !== -1) return "secp256k1";
		if ("|secp384r1|NIST P-384|P-384|".indexOf(s) !== -1) return "secp384r1";
		return null;
	}
}
