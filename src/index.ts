import {Buffer} from "buffer";
import {createHash} from "crypto";

import {sha256_512crypt} from "./sha";
import {md5crypt} from "./md5";

const crypt = (password: string, input: string): string => {
	if (!input.startsWith("$")) 
		throw new Error("Unsupported crypt type.");
	
	const [, algorithm, ...rest] = input.split("$");
	switch (algorithm) {
		case "1":
			return md5crypt(password, rest[0]);
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

export default crypt;
