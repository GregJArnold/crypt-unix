import {Buffer} from "buffer";
import {createHash} from "crypto";

import {b64_from_24bit} from "./util";

export const md5crypt = (password: string, salt: string): string => {
	const maxSaltLen = 8;
	const len = 16;
	const saltBuf = Buffer.from(salt.substring(0, maxSaltLen));
	const key = Buffer.from(password);

	const hashA = createHash("md5");
	hashA.update(key);
	hashA.update("$1$");
	hashA.update(saltBuf);

	const hashB = createHash("md5");
	hashB.update(key);
	hashB.update(saltBuf);
	hashB.update(key)
	const hashBResult = hashB.digest();

	let i = key.length;
	for (; i > len; i -= len) hashA.update(hashBResult);
	hashA.update(hashBResult.subarray(0, i));

	const zero = Buffer.alloc(1);
	const pw = key.subarray(0, 1);

	for (let j = key.length; j > 0; j >>>= 1) hashA.update(j & 1 ? zero : pw);

	let hashLoop = hashA.digest();
	for (let r = 0; r < 1000; r++) {
		const hashC = createHash("md5");
		hashC.update(r & 1 ? key : hashLoop);
		if (r % 3) hashC.update(saltBuf);
		if (r % 7) hashC.update(key);
		hashC.update(r & 1 ? hashLoop : key);
		hashLoop = hashC.digest();
	}

	let outStr = "";
	outStr += b64_from_24bit(hashLoop[0], hashLoop[6], hashLoop[12], 4);
	outStr += b64_from_24bit(hashLoop[1], hashLoop[7], hashLoop[13], 4);
	outStr += b64_from_24bit(hashLoop[2], hashLoop[8], hashLoop[14], 4);
	outStr += b64_from_24bit(hashLoop[3], hashLoop[9], hashLoop[15], 4);
	outStr += b64_from_24bit(hashLoop[4], hashLoop[10], hashLoop[5], 4);
	outStr += b64_from_24bit(0, 0, hashLoop[11], 2);
	return `$1$${saltBuf.toString()}$${outStr}`;
}
