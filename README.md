# crypt-unix
A pure-JavaScript library to provide UNIX/Linux `crypt(1)`.  It uses Node's `crypto` for the cryptography.  This tool allows you to generate and verify passwords as used in UNIX's/Linux's `/etc/shadow` file, or other tools that generate the same format.

| ID                | Scheme  | Supported |
| ----------------- | ------- | --------- |
|	                  | DES     | :x:       |
| _                 | BSDi    | :x:       |
| 1                 | MD5     | ✅        |
| 2, 2a, 2b, 2x, 2y | bcrypt  | :x:       |
| 3                 | NTHASH  | :x:       |
| 5                 | SHA-256 | ✅        |
| 6                 | SHA-512 | ✅        |
| 7                 | scrypt  | :x:       |

The unsupported formats will be added in future releases - `v1.0.0` should have all of these formats available.

## Export and Example
This file just has the default export: `crypt(string password, string salt): boolean`.

```typescript
import crypt from 'crypt-unix';

const hashedPassword = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

function verifyPassword(string enteredPassword): boolean {
  return crypt(enteredPassword, hashedPassword) === hashedPassword;
}
```
