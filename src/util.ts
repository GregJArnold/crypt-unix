const b64Str = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export const b64_from_24bit = (a: number, b: number, c: number, len: number): string => {
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
