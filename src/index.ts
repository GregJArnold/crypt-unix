import {Buffer} from "buffer";
import {createHash} from "crypto";

const b64Str = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const b64_from_24bit = (a: number, b: number, c: number, len: number): string => {
	let ret = "";
	let w = (a << 16) | (b << 8) | c;
	ret += b64Str.substr(w & 0x3f, 1);
	w >>>= 6;
	ret += b64Str.substr(w & 0x3f, 1);
	w >>>= 6;
	ret += b64Str.substr(w & 0x3f, 1);
	w >>>= 6;
	ret += b64Str.substr(w & 0x3f, 1);
	return ret.substr(0, len);
};

const crypt = (password: string, input: string): string => {
	if (!input.startsWith("$")) 
		throw new Error("Unsupported crypt type.");
	
	const [, algorithm, ...rest] = input.split("$");
	switch (algorithm) {
		case "5":
		case "6":
			let [maybeRounds, salt] = rest;
			let rounds: number | undefined;
			if (maybeRounds.startsWith("rounds=")) {
				rounds = parseInt(maybeRounds.substring(7), 10);
			} else {
				salt = maybeRounds;
			}
			return sha256_512crypt(algorithm, password, salt, rounds);
		default:
			throw new Error("Unsupported crypt type.");
	}
};

const sha256_512crypt = (algorithm: "5" | "6", password: string, salt: string, rounds: number | undefined): string => {
	const hash = algorithm === "5" ? "sha256" : "sha512";
	const len = algorithm === "5" ? 32 : 64;
	const maxSaltLen = 16;
	const key = Buffer.from(password);
	const saltBuf = Buffer.from(salt.substring(0, maxSaltLen));

	if (rounds && rounds < 1000) rounds = 1000;
	if (rounds && rounds > 999999999) rounds = 999999999;

	const hashA = createHash(hash);
	hashA.update(key);
	hashA.update(saltBuf);

	const hashB = createHash(hash);
	hashB.update(key);
	hashB.update(saltBuf);
	hashB.update(key);
	const hashBResult = hashB.digest();

	let i = key.length;
	for (; i > len; i -= len) hashA.update(hashBResult);
	hashA.update(hashBResult.subarray(0, i));

	for (let j = key.length; j > 0; j >>>= 1) hashA.update(j & 1 ? hashBResult : key);

	const hashAResult = hashA.digest();

	const hashDP = createHash(hash);
	for (let j = 0; j < key.length; j++) hashDP.update(key);
	const hashDPResult = hashDP.digest();

	const bufP = Buffer.alloc(key.length);
	for (i = 0; i + len < key.length; i += len) hashDPResult.copy(bufP, i);
	hashDPResult.copy(bufP, i, 0, key.length - i);

	const hashDS = createHash(hash);
	for (let j = 0; j < 16 + hashAResult[0]; j++) hashDS.update(saltBuf);
	const hashDSResult = hashDS.digest();

	const bufS = Buffer.alloc(saltBuf.length);
	for (i = 0; i + len < saltBuf.length; i += len) hashDSResult.copy(bufS, i);
	hashDSResult.copy(bufS, i, 0, saltBuf.length - i);

	let hashAC = hashAResult;
	for (let r = 0; r < (rounds ?? 5000); r++) {
		const hashC = createHash(hash);
		hashC.update(r & 1 ? bufP : hashAC);
		if (r % 3) hashC.update(bufS);
		if (r % 7) hashC.update(bufP);
		hashC.update(r & 1 ? hashAC : bufP);
		hashAC = hashC.digest();
	}

	let outStr = "";
	if (algorithm === "5") {
		outStr += b64_from_24bit(hashAC[0], hashAC[10], hashAC[20], 4);
		outStr += b64_from_24bit(hashAC[21], hashAC[1], hashAC[11], 4);
		outStr += b64_from_24bit(hashAC[12], hashAC[22], hashAC[2], 4);
		outStr += b64_from_24bit(hashAC[3], hashAC[13], hashAC[23], 4);
		outStr += b64_from_24bit(hashAC[24], hashAC[4], hashAC[14], 4);
		outStr += b64_from_24bit(hashAC[15], hashAC[25], hashAC[5], 4);
		outStr += b64_from_24bit(hashAC[6], hashAC[16], hashAC[26], 4);
		outStr += b64_from_24bit(hashAC[27], hashAC[7], hashAC[17], 4);
		outStr += b64_from_24bit(hashAC[18], hashAC[28], hashAC[8], 4);
		outStr += b64_from_24bit(hashAC[9], hashAC[19], hashAC[29], 4);
		outStr += b64_from_24bit(0, hashAC[31], hashAC[30], 3);
	} else {
		outStr += b64_from_24bit(hashAC[0], hashAC[21], hashAC[42], 4);
		outStr += b64_from_24bit(hashAC[22], hashAC[43], hashAC[1], 4);
		outStr += b64_from_24bit(hashAC[44], hashAC[2], hashAC[23], 4);
		outStr += b64_from_24bit(hashAC[3], hashAC[24], hashAC[45], 4);
		outStr += b64_from_24bit(hashAC[25], hashAC[46], hashAC[4], 4);
		outStr += b64_from_24bit(hashAC[47], hashAC[5], hashAC[26], 4);
		outStr += b64_from_24bit(hashAC[6], hashAC[27], hashAC[48], 4);
		outStr += b64_from_24bit(hashAC[28], hashAC[49], hashAC[7], 4);
		outStr += b64_from_24bit(hashAC[50], hashAC[8], hashAC[29], 4);
		outStr += b64_from_24bit(hashAC[9], hashAC[30], hashAC[51], 4);
		outStr += b64_from_24bit(hashAC[31], hashAC[52], hashAC[10], 4);
		outStr += b64_from_24bit(hashAC[53], hashAC[11], hashAC[32], 4);
		outStr += b64_from_24bit(hashAC[12], hashAC[33], hashAC[54], 4);
		outStr += b64_from_24bit(hashAC[34], hashAC[55], hashAC[13], 4);
		outStr += b64_from_24bit(hashAC[56], hashAC[14], hashAC[35], 4);
		outStr += b64_from_24bit(hashAC[15], hashAC[36], hashAC[57], 4);
		outStr += b64_from_24bit(hashAC[37], hashAC[58], hashAC[16], 4);
		outStr += b64_from_24bit(hashAC[59], hashAC[17], hashAC[38], 4);
		outStr += b64_from_24bit(hashAC[18], hashAC[39], hashAC[60], 4);
		outStr += b64_from_24bit(hashAC[40], hashAC[61], hashAC[19], 4);
		outStr += b64_from_24bit(hashAC[62], hashAC[20], hashAC[41], 4);
		outStr += b64_from_24bit(0, 0, hashAC[63], 2);
	}

	return `$${algorithm}$${rounds ? `rounds=${rounds}$` : ""}${saltBuf.toString()}$${outStr}`;
};

export default crypt;
