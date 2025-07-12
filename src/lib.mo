/*******************************************************************
* Copyright         : 2025 nirvana369
* File Name         : lib.mo
* Description       : hmac-sha512.
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 10/07/2025		nirvana369 		implement
******************************************************************/
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import Int "mo:base/Int";
import Int64 "mo:base/Int64";
import Text "mo:base/Text";
import Nat64 "mo:base/Nat64";
import Char "mo:base/Char";
import Int32 "mo:base/Int32";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Utils "./utils";

module {

    // ========== TYPE DEFINITIONS ==========

    public type InputType = {
        #text : Text;
        #hex : Text;
        #blob : Blob;
        #bytes : [Nat8];
    };

    private type PackedValue = {
        value : [Int64];
        binLen : Int;
    };

    private type Int_64 = {
        highOrder: Int64;
        lowOrder: Int64;
    };

    // ========== CONSTANTS ==========
    private let TWO_PWR_32 : Int64 = 4294967296;
    private let BLOCK_SIZE_512 : Int = 1024;
    private let OUTPUT_LEN_512 : Nat = 512;
    private let BYTES_PER_WORD : Nat = 4;
    private let BITS_PER_BYTE : Nat = 8;
    private let SHA512_ROUNDS : Nat = 80;

    /* Constants used in SHA-2 families */
    private let K_sha2 : [Int64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    private let H_full : [Int64] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    // ========== UTILITY FUNCTIONS ==========
    private func getInput(data : InputType) : (Text) {
        switch (data) {
            case (#text v) (Utils.bytesToHex(Blob.toArray(Text.encodeUtf8(v))));
            case (#hex v) v;
            case (#bytes(v))  Utils.bytesToHex(v);
            case (#blob(v)) {
                let b = Blob.toArray(v);
                (Utils.bytesToHex(b));
            };
        };
    };

    // ========== CORE HASHING FUNCTIONS ==========

    /// Converts a hex text to an array of packed words
    private func hexToPacked(
        hexString: Text,
        existingPacked: ?[Int64],
        existingPackedLen: ?Int,
        bigEndianMod: Int // -1 or 1
    ): PackedValue {
        if (hexString.size() % 2 != 0) {
            Debug.trap("Hex string must be in byte increments");
        };

        let initialPackedLen = switch (existingPackedLen) { case (?v) v; case null 0 };
        let packedBuffer = switch(existingPacked) {
            case null Buffer.fromArray<Int64>([]);
            case (?arr) Buffer.fromArray<Int64>(arr);
        };

        let existingByteLen = Int64.fromInt(initialPackedLen) >> 3;
        let shiftModifier : Int64 = if (bigEndianMod == -1) 3 else 0;
        let modBE = Int64.fromInt(bigEndianMod);
        let chars = Text.toArray(hexString);

        var i = 0;
        while (i < chars.size()) {
            let bytePair = Char.toText(chars[i]) # Char.toText(chars[i+1]);
            let byteValue = Int64.fromInt(Utils.hexToInt(bytePair));
            let byteOffset = (Int64.fromNat64(Nat64.fromNat(i) >> 1)) + existingByteLen;
            let intOffset = byteOffset >> 2;

            let bufferIndex = Nat64.toNat(Int64.toNat64(intOffset));
            while (packedBuffer.size() <= bufferIndex) {
                packedBuffer.add(0);
            };

            let shiftAmount = 8 * (shiftModifier + modBE * (byteOffset % 4));
            packedBuffer.put(bufferIndex, packedBuffer.get(bufferIndex) | (byteValue << shiftAmount));
            i += 2;
        };

        { 
            value = Buffer.toArray(packedBuffer); 
            binLen = chars.size() * 4 + initialPackedLen 
        }
    };

    /// Converts packed words to a hexadecimal text
    private func packedToHex(
        packed: [Int64],
        outputLength: Nat,
        bigEndianMod: Int, // -1 or 1
    ): Text {
        let HEX_TAB : [Char] = Text.toArray("0123456789abcdef");
        var result = "";
        let byteCount = outputLength / BITS_PER_BYTE;
        let shiftModifier : Int64 = if (bigEndianMod == -1) 3 else 0;

        for (i in Iter.range(0, byteCount - 1)) {
            let wordIndex = Nat64.toNat(Nat64.fromNat(i) >> 2);
            let bytePosition = Int64.fromNat64(Nat64.fromNat(i));
            let srcByte = packed[wordIndex] >> (8 * (shiftModifier + Int64.fromInt(bigEndianMod) * (bytePosition % 4)));
            
            let highNibble = Nat64.toNat(Int64.toNat64(srcByte >> 4 & 0xf));
            let lowNibble = Nat64.toNat(Int64.toNat64(srcByte & 0xf)); 
            result #= Char.toText(HEX_TAB[highNibble]) # Char.toText(HEX_TAB[lowNibble]);
        };

        result;
    };

    // ========== BITWISE OPERATIONS ==========

    /// 64-bit implementation of circular rotate left
    private func rotateLeft64(x: Int_64, n: Int64): Int_64 {
        if (n > 32) {
            let combined = (x.highOrder << 32) | x.lowOrder;
            let rotated = Int64.bitrotLeft(combined, n);
            { highOrder = (rotated >> 32) & 0xffffffff; lowOrder = rotated & 0xffffffff }
        } else if (n != 0) {
            let shift = 32 - n;
            { 
                highOrder = (x.highOrder << n) | (x.lowOrder >> shift); 
                lowOrder = (x.lowOrder << n) | (x.highOrder >> shift)
            }
        } else {
            x
        }
    };

    /// 64-bit implementation of circular rotate right
    private func rotateRight64(x: Int_64, n: Int64): Int_64 {
        if (n < 32) {
            let shift = 32 - n;
            { 
                highOrder = ((x.highOrder >> n) | (x.lowOrder << shift)) & 0xffffffff; 
                lowOrder = ((x.lowOrder >> n) | (x.highOrder << shift)) & 0xffffffff
            }
        } else {
            let combined = (x.highOrder << 32) | x.lowOrder;
            let rotated = Int64.bitrotRight(combined, n);
            { highOrder = (rotated >> 32) & 0xffffffff; lowOrder = rotated & 0xffffffff }
        }
    };

    /// 64-bit implementation of shift right
    private func shiftRight64(x: Int_64, n: Int64): Int_64 {
        { 
            highOrder = (x.highOrder >> n) & 0xffffffff; 
            lowOrder = ((x.lowOrder >> n) | (x.highOrder << (32 - n))) & 0xffffffff 
        }
    };

    // ========== SHA-2 LOGIC FUNCTIONS ==========

    /// The 64-bit implementation of the NIST specified Ch function
    private func ch64(x: Int_64, y: Int_64, z: Int_64): Int_64 {
        { 
            highOrder = (x.highOrder & y.highOrder) ^ (Int64.bitnot(x.highOrder) & z.highOrder);
            lowOrder = (x.lowOrder & y.lowOrder) ^ (Int64.bitnot(x.lowOrder) & z.lowOrder)
        }
    };

    /// The 64-bit implementation of the NIST specified Maj function
    private func maj64(x: Int_64, y: Int_64, z: Int_64): Int_64 {
        { 
            highOrder = (x.highOrder & y.highOrder) ^ (x.highOrder & z.highOrder) ^ (y.highOrder & z.highOrder);
            lowOrder = (x.lowOrder & y.lowOrder) ^ (x.lowOrder & z.lowOrder) ^ (y.lowOrder & z.lowOrder)
        }
    };

    /// The 64-bit implementation of the NIST specified Sigma0 function
    private func sigma064(x: Int_64): Int_64 {
        let rotr28 = rotateRight64(x, 28);
        let rotr34 = rotateRight64(x, 34);
        let rotr39 = rotateRight64(x, 39);

        { 
            highOrder = rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder;
            lowOrder = rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder
        }
    };

    /// The 64-bit implementation of the NIST specified Sigma1 function
    private func sigma164(x: Int_64): Int_64 {
        let rotr14 = rotateRight64(x, 14);
        let rotr18 = rotateRight64(x, 18);
        let rotr41 = rotateRight64(x, 41);
        { 
            highOrder = rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder;
            lowOrder = rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder
        }
    };

    /// The 64-bit implementation of the NIST specified Gamma0 function
    private func gamma064(x: Int_64): Int_64 {
        let rotr1 = rotateRight64(x, 1);
        let rotr8 = rotateRight64(x, 8);
        let shr7 = shiftRight64(x, 7);

        { 
            highOrder = rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder;
            lowOrder = rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder
        }
    };

    /// The 64-bit implementation of the NIST specified Gamma1 function
    private func gamma164(x: Int_64): Int_64 {
        let rotr19 = rotateRight64(x, 19);
        let rotr61 = rotateRight64(x, 61);
        let shr6 = shiftRight64(x, 6);

        { 
            highOrder = rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder;
            lowOrder = rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder
        }
    };

    // ========== ARITHMETIC OPERATIONS ==========

    /// Adds two 64-bit integers with overflow protection
    private func safeAdd64_2(x: Int_64, y: Int_64): Int_64 {
        var lsw = (x.lowOrder & 0xffff) + (y.lowOrder & 0xffff);
        var msw = (x.lowOrder >> 16) + (y.lowOrder >> 16) + (lsw >> 16);
        let low = ((msw & 0xffff) << 16) | (lsw & 0xffff);

        lsw := (x.highOrder & 0xffff) + (y.highOrder & 0xffff) + (msw >> 16);
        msw := (x.highOrder >> 16) + (y.highOrder >> 16) + (lsw >> 16);
        let high = ((msw & 0xffff) << 16) | (lsw & 0xffff);

        { highOrder = high; lowOrder = low }
    };

    /// Adds four 64-bit integers with overflow protection
    private func safeAdd64_4(a: Int_64, b: Int_64, c: Int_64, d: Int_64): Int_64 {
        var lsw = (a.lowOrder & 0xffff) + (b.lowOrder & 0xffff) + (c.lowOrder & 0xffff) + (d.lowOrder & 0xffff);
        var msw = (a.lowOrder >> 16) + (b.lowOrder >> 16) + (c.lowOrder >> 16) + (d.lowOrder >> 16) + (lsw >> 16);
        let low = ((msw & 0xffff) << 16) | (lsw & 0xffff);

        lsw := (a.highOrder & 0xffff) + (b.highOrder & 0xffff) + (c.highOrder & 0xffff) + (d.highOrder & 0xffff) + (msw >> 16);
        msw := (a.highOrder >> 16) + (b.highOrder >> 16) + (c.highOrder >> 16) + (d.highOrder >> 16) + (lsw >> 16);
        let high = ((msw & 0xffff) << 16) | (lsw & 0xffff);

        { highOrder = high; lowOrder = low }
    };

    /// Adds five 64-bit integers with overflow protection
    private func safeAdd64_5(a: Int_64, b: Int_64, c: Int_64, d: Int_64, e: Int_64): Int_64 {
        var lsw = (a.lowOrder & 0xffff) + (b.lowOrder & 0xffff) + (c.lowOrder & 0xffff) + (d.lowOrder & 0xffff) + (e.lowOrder & 0xffff);
        var msw = (a.lowOrder >> 16) + (b.lowOrder >> 16) + (c.lowOrder >> 16) + (d.lowOrder >> 16) + (e.lowOrder >> 16) + (lsw >> 16);
        let low = ((msw & 0xffff) << 16) | (lsw & 0xffff);

        lsw := (a.highOrder & 0xffff) + (b.highOrder & 0xffff) + (c.highOrder & 0xffff) + (d.highOrder & 0xffff) + (e.highOrder & 0xffff) + (msw >> 16);
        msw := (a.highOrder >> 16) + (b.highOrder >> 16) + (c.highOrder >> 16) + (d.highOrder >> 16) + (e.highOrder >> 16) + (lsw >> 16);
        let high = ((msw & 0xffff) << 16) | (lsw & 0xffff);

        { highOrder = high; lowOrder = low }
    };

    /// XORs two 64-bit integers
    private func xor64_2(a: Int_64, b: Int_64): Int_64 {
        { highOrder = a.highOrder ^ b.highOrder; lowOrder = a.lowOrder ^ b.lowOrder }
    };

    /// XORs five 64-bit integers
    private func xor64_5(a: Int_64, b: Int_64, c: Int_64, d: Int_64, e: Int_64): Int_64 {
        { 
            highOrder = a.highOrder ^ b.highOrder ^ c.highOrder ^ d.highOrder ^ e.highOrder;
            lowOrder = a.lowOrder ^ b.lowOrder ^ c.lowOrder ^ d.lowOrder ^ e.lowOrder
        }
    };

    // ========== SHA-512 SPECIFIC FUNCTIONS ==========

    /// Creates a new initial state for SHA-512
    private func getNewState512(): [Int_64] {
        [
            { highOrder = H_full[0]; lowOrder = 0xf3bcc908 },
            { highOrder = H_full[1]; lowOrder = 0x84caa73b },
            { highOrder = H_full[2]; lowOrder = 0xfe94f82b },
            { highOrder = H_full[3]; lowOrder = 0x5f1d36f1 },
            { highOrder = H_full[4]; lowOrder = 0xade682d1 },
            { highOrder = H_full[5]; lowOrder = 0x2b3e6c1f },
            { highOrder = H_full[6]; lowOrder = 0xfb41bd6b },
            { highOrder = H_full[7]; lowOrder = 0x137e2179 },
        ]
    };

    public class HmacSha512() {
        // SHA-512 constants
        let K_sha512 : [Int_64] = [
            { highOrder = K_sha2[0]; lowOrder = 0xd728ae22 },
            { highOrder = K_sha2[1]; lowOrder = 0x23ef65cd },
            { highOrder = K_sha2[2]; lowOrder = 0xec4d3b2f },
            { highOrder = K_sha2[3]; lowOrder = 0x8189dbbc },
            { highOrder = K_sha2[4]; lowOrder = 0xf348b538 },
            { highOrder = K_sha2[5]; lowOrder = 0xb605d019 },
            { highOrder = K_sha2[6]; lowOrder = 0xaf194f9b },
            { highOrder = K_sha2[7]; lowOrder = 0xda6d8118 },
            { highOrder = K_sha2[8]; lowOrder = 0xa3030242 },
            { highOrder = K_sha2[9]; lowOrder = 0x45706fbe },
            { highOrder = K_sha2[10]; lowOrder = 0x4ee4b28c },
            { highOrder = K_sha2[11]; lowOrder = 0xd5ffb4e2 },
            { highOrder = K_sha2[12]; lowOrder = 0xf27b896f },
            { highOrder = K_sha2[13]; lowOrder = 0x3b1696b1 },
            { highOrder = K_sha2[14]; lowOrder = 0x25c71235 },
            { highOrder = K_sha2[15]; lowOrder = 0xcf692694 },
            { highOrder = K_sha2[16]; lowOrder = 0x9ef14ad2 },
            { highOrder = K_sha2[17]; lowOrder = 0x384f25e3 },
            { highOrder = K_sha2[18]; lowOrder = 0x8b8cd5b5 },
            { highOrder = K_sha2[19]; lowOrder = 0x77ac9c65 },
            { highOrder = K_sha2[20]; lowOrder = 0x592b0275 },
            { highOrder = K_sha2[21]; lowOrder = 0x6ea6e483 },
            { highOrder = K_sha2[22]; lowOrder = 0xbd41fbd4 },
            { highOrder = K_sha2[23]; lowOrder = 0x831153b5 },
            { highOrder = K_sha2[24]; lowOrder = 0xee66dfab },
            { highOrder = K_sha2[25]; lowOrder = 0x2db43210 },
            { highOrder = K_sha2[26]; lowOrder = 0x98fb213f },
            { highOrder = K_sha2[27]; lowOrder = 0xbeef0ee4 },
            { highOrder = K_sha2[28]; lowOrder = 0x3da88fc2 },
            { highOrder = K_sha2[29]; lowOrder = 0x930aa725 },
            { highOrder = K_sha2[30]; lowOrder = 0xe003826f },
            { highOrder = K_sha2[31]; lowOrder = 0x0a0e6e70 },
            { highOrder = K_sha2[32]; lowOrder = 0x46d22ffc },
            { highOrder = K_sha2[33]; lowOrder = 0x5c26c926 },
            { highOrder = K_sha2[34]; lowOrder = 0x5ac42aed },
            { highOrder = K_sha2[35]; lowOrder = 0x9d95b3df },
            { highOrder = K_sha2[36]; lowOrder = 0x8baf63de },
            { highOrder = K_sha2[37]; lowOrder = 0x3c77b2a8 },
            { highOrder = K_sha2[38]; lowOrder = 0x47edaee6 },
            { highOrder = K_sha2[39]; lowOrder = 0x1482353b },
            { highOrder = K_sha2[40]; lowOrder = 0x4cf10364 },
            { highOrder = K_sha2[41]; lowOrder = 0xbc423001 },
            { highOrder = K_sha2[42]; lowOrder = 0xd0f89791 },
            { highOrder = K_sha2[43]; lowOrder = 0x0654be30 },
            { highOrder = K_sha2[44]; lowOrder = 0xd6ef5218 },
            { highOrder = K_sha2[45]; lowOrder = 0x5565a910 },
            { highOrder = K_sha2[46]; lowOrder = 0x5771202a },
            { highOrder = K_sha2[47]; lowOrder = 0x32bbd1b8 },
            { highOrder = K_sha2[48]; lowOrder = 0xb8d2d0c8 },
            { highOrder = K_sha2[49]; lowOrder = 0x5141ab53 },
            { highOrder = K_sha2[50]; lowOrder = 0xdf8eeb99 },
            { highOrder = K_sha2[51]; lowOrder = 0xe19b48a8 },
            { highOrder = K_sha2[52]; lowOrder = 0xc5c95a63 },
            { highOrder = K_sha2[53]; lowOrder = 0xe3418acb },
            { highOrder = K_sha2[54]; lowOrder = 0x7763e373 },
            { highOrder = K_sha2[55]; lowOrder = 0xd6b2b8a3 },
            { highOrder = K_sha2[56]; lowOrder = 0x5defb2fc },
            { highOrder = K_sha2[57]; lowOrder = 0x43172f60 },
            { highOrder = K_sha2[58]; lowOrder = 0xa1f0ab72 },
            { highOrder = K_sha2[59]; lowOrder = 0x1a6439ec },
            { highOrder = K_sha2[60]; lowOrder = 0x23631e28 },
            { highOrder = K_sha2[61]; lowOrder = 0xde82bde9 },
            { highOrder = K_sha2[62]; lowOrder = 0xb2c67915 },
            { highOrder = K_sha2[63]; lowOrder = 0xe372532b },
            { highOrder = 0xca273ece; lowOrder = 0xea26619c },
            { highOrder = 0xd186b8c7; lowOrder = 0x21c0c207 },
            { highOrder = 0xeada7dd6; lowOrder = 0xcde0eb1e },
            { highOrder = 0xf57d4f7f; lowOrder = 0xee6ed178 },
            { highOrder = 0x06f067aa; lowOrder = 0x72176fba },
            { highOrder = 0x0a637dc5; lowOrder = 0xa2c898a6 },
            { highOrder = 0x113f9804; lowOrder = 0xbef90dae },
            { highOrder = 0x1b710b35; lowOrder = 0x131c471b },
            { highOrder = 0x28db77f5; lowOrder = 0x23047d84 },
            { highOrder = 0x32caab7b; lowOrder = 0x40c72493 },
            { highOrder = 0x3c9ebe0a; lowOrder = 0x15c9bebc },
            { highOrder = 0x431d67c4; lowOrder = 0x9c100d4c },
            { highOrder = 0x4cc5d4be; lowOrder = 0xcb3e42b6 },
            { highOrder = 0x597f299c; lowOrder = 0xfc657e2a },
            { highOrder = 0x5fcb6fab; lowOrder = 0x3ad6faec },
            { highOrder = 0x6c44198c; lowOrder = 0x4a475817 },
        ];

        // Instance variables
        var intermediateState : [Int_64] = getNewState512();
        var macKeySet = false;
        var keyWithIPad: [var Int64] = [var];
        var keyWithOPad: [var Int64] = [var];
        var remainder: [Int64] = [];
        var remainderLen: Int = 0;
        var updateCalled: Bool = false;
        var processedLen: Int = 0;

        // Constants
        let BIG_ENDIAN_MOD = -1;
        let HMAC_SUPPORTED = true;
        let SHA_VARIANT = "SHA-512";

        /// Initializes the SHA-512 instance with options
        public func init(input : InputType) {
            let hmacKey = getInput(input);
            _setHMACKey(hexToPacked(hmacKey, null, null, BIG_ENDIAN_MOD));
        };

        /// Performs a round of SHA-512 hashing over a block
        private func processBlock(block: [Int64], H: [Int_64]): [Int_64] {
            let W = Array.tabulateVar<Int_64>(SHA512_ROUNDS, func i = { highOrder = 0; lowOrder = 0 });

            var a = H[0];
            var b = H[1];
            var c = H[2];
            var d = H[3];
            var e = H[4];
            var f = H[5];
            var g = H[6];
            var h = H[7];

            for (t in Iter.range(0, SHA512_ROUNDS - 1)) {
                if (t < 16) {
                    let offset = t * 2;
                    W[t] := { highOrder = block[offset]; lowOrder = block[offset + 1] };
                } else {
                    W[t] := safeAdd64_4(gamma164(W[t - 2]), W[t - 7], gamma064(W[t - 15]), W[t - 16]);
                };

                let T1 = safeAdd64_5(h, sigma164(e), ch64(e, f, g), K_sha512[t], W[t]);
                let T2 = safeAdd64_2(sigma064(a), maj64(a, b, c));
                
                h := g;
                g := f;
                f := e;
                e := safeAdd64_2(d, T1);
                d := c;
                c := b;
                b := a;
                a := safeAdd64_2(T1, T2);
            };

            [
                safeAdd64_2(a, H[0]),
                safeAdd64_2(b, H[1]),
                safeAdd64_2(c, H[2]),
                safeAdd64_2(d, H[3]),
                safeAdd64_2(e, H[4]),
                safeAdd64_2(f, H[5]),
                safeAdd64_2(g, H[6]),
                safeAdd64_2(h, H[7])
            ]
        };

        /// Finalizes the SHA-512 hash
        private func finalizeHash(
            remain: [Int64],
            remainderBinLen: Int,
            processedBinLen: Int,
            H: [Int_64]
        ): [Int64] {
            // Calculate padding position
            let offset = (((Int64.fromInt(remainderBinLen) + 129) >> 10) << 5) + 31;
            let totalLen = Int64.fromInt(remainderBinLen + processedBinLen);
            
            let remainderBuffer = Buffer.fromArray<Int64>(remain);
            let offsetNat = Int.abs(Int64.toInt(offset));

            // Pad the remainder buffer
            while (remainderBuffer.size() <= offsetNat) {
                remainderBuffer.add(0);
            };
            
            // Append '1' bit
            let j = Int.abs(Int64.toInt(Int64.fromInt(remainderBinLen) >> 5));
            remainderBuffer.put(j, remainderBuffer.get(j) | (0x80 << (24 - (Int64.fromInt(remainderBinLen) % 32))));

            // Append length
            remainderBuffer.put(offsetNat, totalLen & 0xffffffff);
            remainderBuffer.put(offsetNat - 1, (totalLen / TWO_PWR_32) | 0);

            var state = H;

            // Process all blocks
            var i = 0;
            while (i < remainderBuffer.size()) {
                state := processBlock(Buffer.toArray(Buffer.subBuffer(remainderBuffer, i, 32)), state);
                i += 32;
            };

            // Convert state to output format
            [
                state[0].highOrder, state[0].lowOrder,
                state[1].highOrder, state[1].lowOrder,
                state[2].highOrder, state[2].lowOrder,
                state[3].highOrder, state[3].lowOrder,
                state[4].highOrder, state[4].lowOrder,
                state[5].highOrder, state[5].lowOrder,
                state[6].highOrder, state[6].lowOrder,
                state[7].highOrder, state[7].lowOrder,
            ]
        };

        /// Internal function that sets the HMAC key
        private func _setHMACKey(key: PackedValue) {
            let blockByteSize = Int64.fromInt(BLOCK_SIZE_512) >> 3;
            let lastArrayIndex = blockByteSize / 4 - 1;

            if (macKeySet) Debug.trap("MAC key already set");

            // Process key based on its size
            var keyBuffer = Buffer.fromArray<Int64>(key.value);
            if (Int64.toInt(blockByteSize) < key.binLen / 8) {
                let finalized = finalizeHash(key.value, key.binLen, 0, getNewState512());
                keyBuffer := Buffer.fromArray(finalized);
            };

            // Pad key buffer if needed
            let arrLength = Int.abs(Int64.toInt(lastArrayIndex));
            while (keyBuffer.size() <= arrLength) {
                keyBuffer.add(0);
            };

            // Create ipad and opad
            keyWithIPad := Array.tabulateVar<Int64>(arrLength + 1, func i = 0);
            keyWithOPad := Array.tabulateVar<Int64>(arrLength + 1, func i = 0);
            
            for (i in Iter.range(0, arrLength)) {
                keyWithIPad[i] := keyBuffer.get(i) ^ 0x36363636;
                keyWithOPad[i] := keyBuffer.get(i) ^ 0x5c5c5c5c;
            };

            // Initialize HMAC processing
            intermediateState := processBlock(Array.freeze(keyWithIPad), intermediateState);
            processedLen := BLOCK_SIZE_512;
            macKeySet := true;
        };

        /// Updates the hash with new data
        public func update(input: InputType) {
            let srcString = getInput(input);
            var updateProcessedLen = 0;
            let chunkInfo = hexToPacked(srcString, ?remainder, ?remainderLen, BIG_ENDIAN_MOD);
            let chunkBinLen = chunkInfo.binLen;
            let chunk = chunkInfo.value;
            let chunkIntLen = Int.abs(Int64.toInt(Int64.fromInt(chunkBinLen) >> 5));

            // Process all complete blocks
            var i = 0;
            while (i < chunkIntLen) {
                if (updateProcessedLen + BLOCK_SIZE_512 <= chunkBinLen) {
                    intermediateState := processBlock(
                        Array.subArray(chunk, i, Int.abs(Int64.toInt(Int64.fromInt(BLOCK_SIZE_512) >> 5))), 
                        intermediateState
                    );
                    updateProcessedLen += Int.abs(BLOCK_SIZE_512);
                };
                i += Int.abs(Int64.toInt(Int64.fromInt(BLOCK_SIZE_512) >> 5));
            };

            processedLen += updateProcessedLen;
            let processedWords = Int.abs(Int64.toInt(Int64.fromInt(updateProcessedLen) >> 5));
            
            // Store remaining data
            remainder := Array.subArray(chunk, processedWords, chunk.size() - processedWords);
            remainderLen := chunkBinLen % BLOCK_SIZE_512;
            updateCalled := true;
        };

        /// Internal function to compute HMAC
        private func _getHMAC(): [Int64] {
            if (not macKeySet) Debug.trap("Cannot call getHMAC without first setting MAC key");

            let firstHash = finalizeHash(remainder, remainderLen, processedLen, intermediateState);
            var finalizedState = processBlock(Array.freeze(keyWithOPad), getNewState512());
            finalizeHash(firstHash, OUTPUT_LEN_512, BLOCK_SIZE_512, finalizedState)
        };

        /// Gets the HMAC result
        public func getHMAC(): [Nat8] {
            Utils.hexToBytes(packedToHex(_getHMAC(), OUTPUT_LEN_512, BIG_ENDIAN_MOD));
        };

        /// Gets the hash result
        public func digest(): [Nat8] {
            if (macKeySet) {
                return Utils.hexToBytes(packedToHex(_getHMAC(), OUTPUT_LEN_512, BIG_ENDIAN_MOD));
            };
            var finalizedState = finalizeHash(remainder, remainderLen, processedLen, intermediateState);
            
            Utils.hexToBytes(packedToHex(finalizedState, OUTPUT_LEN_512, BIG_ENDIAN_MOD));
        };

        /// Gets the hex result
        public func hexdigest(): Text {
            if (macKeySet) {
                return packedToHex(_getHMAC(), OUTPUT_LEN_512, BIG_ENDIAN_MOD);
            };
            var finalizedState = finalizeHash(remainder, remainderLen, processedLen, intermediateState);
            
            packedToHex(finalizedState, OUTPUT_LEN_512, BIG_ENDIAN_MOD);
        };
    };
}