import crypt from '../src/index';

describe('testing sha256crypt', () => {
	const tests = [
		{
			name: "Basic test",
			salt: "$5$saltstring",
			pass: "Hello world!",
			value: "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		},
		{
			name: "Test with rounds and truncated salt",
			salt: "$5$rounds=10000$saltstringsaltstring",
			pass: "Hello world!",
			value: "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
		},
		{
			name: "Default but given rounds and truncated salt",
			salt: "$5$rounds=5000$toolongsaltstring",
			pass: "This is just a test",
			value: "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
		},
		{
			name: "Test with longer password",
			salt: "$5$rounds=1400$anotherlongsaltstring",
			pass: "a very much longer text to encrypt.  This one even stretches over morethan one line.",
			value: "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
		},
		{
			name: "Test with short salt",
			salt: "$5$rounds=77777$short",
			pass: "we have a short salt string but not a short password",
			value: "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"
		},
		{
			name: "Test with 16-character salt",
			salt: "$5$rounds=123456$asaltof16chars..",
			pass: "a short string",
			value: "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD",
		},
		{
			name: "Test with rounds too low",
			salt: "$5$rounds=10$roundstoolow",
			pass: "the minimum number is still observed",
			value: "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
		},
	];
	tests.forEach(t => {
		test(t.name, () => {
			expect(crypt(t.pass, t.salt)).toBe(t.value);
		});
	});
});

describe('testing sha512crypt file', () => {
	const tests = [
		{
		name: "Plain salt string",
		salt: "$6$saltstring",
		pass: "Hello world!",
		value: "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
		},
		{
		name: "Number of rounds plus truncated salt",
		salt: "$6$rounds=10000$saltstringsaltstring",
		pass: "Hello world!",
		value: "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
		},
		{
		name: "Number of rounds is default but given plus truncated salt",
		salt: "$6$rounds=5000$toolongsaltstring",
		pass: "This is just a test",
		value: "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
		},
		{
		name: "Longer string",
		salt: "$6$rounds=1400$anotherlongsaltstring",
		pass: "a very much longer text to encrypt.  This one even stretches over morethan one line.",
		value: "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
		},
		{
		name: "Short salt string",
		salt: "$6$rounds=77777$short",
		pass: "we have a short salt string but not a short password",
		value: "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
		},
		{
		name: "Exactly 16-character salt string",
		salt: "$6$rounds=123456$asaltof16chars..",
		pass: "a short string",
		value: "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
		},
		{
		name: "Rounds under minimum",
		salt: "$6$rounds=10$roundstoolow",
		pass: "the minimum number is still observed",
		value: "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
		},
	];
	tests.forEach(t => {
		test(t.name, () => {
			expect(crypt(t.pass, t.salt)).toBe(t.value);
		});
	});
});
describe('testing md5crypt', () => {
	const tests = [
		{
			name: "Basic test",
			salt: "$1$saltstr1",
			pass: "Hello world!",
			value: "$1$saltstr1$TGPkMH/sRVXxD4j8gJ8Vl1",
		},
		{
			name: "Too-long salt string",
			salt: "$1$saltstring",
			pass: "Hello world!",
			value: "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1",
		},
		{
			name: "Short salt string",
			salt: "$1$salt",
			pass: "Hello world!",
			value: "$1$salt$wa8aFuC3rkp5bjoBIGTc41",
		},
		{
			name: "Hashing a longer string",
			salt: "$1$saltsalt$",
			pass: "A longer string to hash",
			value: "$1$saltsalt$RtXXOeRlX6Gasxuq2h4Rf/",
		},
	];
	tests.forEach(t => {
		test(t.name, () => {
			expect(crypt(t.pass, t.salt)).toBe(t.value);
		});
	});
});
