[![mops](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/mops/hmac-sha512)](https://mops.one/hmac-sha512) [![documentation](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/documentation/hmac-sha512)](https://mops.one/hmac-sha512/docs)

# hmac-sha512

A pure Motoko implementation of HMAC (Hash-based Message Authentication Code) using the SHA-512 cryptographic hash function.

---

## 📦 Installation

Install with mops:

```sh
mops add hmac-sha512
```

## 🔐 HMAC-SHA512 Overview
HMAC-SHA512 provides message authentication using a cryptographic hash function (SHA-512) in combination with a secret key. It provides both data integrity and authenticity verification.


## 🔄 Usage Examples
Basic HMAC-SHA512 Calculation

```
import Lib "mo:hmac-sha512";

// Initialize HMAC-SHA512 with secret key
let hmac = Lib.HmacSha512();
hmac.init(#text "nirvana369");

// Update with message data
hmac.update(#text "message to authenticate");

// Get HMAC as byte array [Nat8]
let hmac = hmac.digest();

// Get HMAC as hex string
let hmacHex = hmac.hexdigest();
```

Using Different Input Formats
```
// Hex input
hmac.update(#HEX("badc0ffee0ddf00d"));

// Bytes input
hmac.update(#bytes ([111, 222, 3, 6, 9]));

// Blob input
hmac.update(#blob (Blob.fromArray([110, 105, 114, 118, 97, 110, 97, 51, 54, 57])));
```

## ⚙️ Advanced Usage
Multiple Updates
```
// Process message in chunks
hmac.update(#text "message ");
hmac.update(#text "part 1");
hmac.update(#text " part 2");
```

## 🧪 Testing
Run tests with mops:
```
mops test
```

## ⚡  Benchmarks
You need mops installed. In your project directory run [Mops](https://mops.one/):

```sh
mops bench
```

[Module benchmarks](https://mops.one/hmac-sha512/benchmarks)

## 📜 License
[MIT License](https://github.com/nirvana369/hmac-sha512/blob/main/LICENSE)