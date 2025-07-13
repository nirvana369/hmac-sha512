/*******************************************************************
* Copyright         : 2025 nirvana369
* File Name         : lib.test.mo
* Description       : test hmac-sha512.
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 12/07/2025		nirvana369 		implement
******************************************************************/

import {test; suite} "mo:test/async";
import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";
import Debug "mo:base/Debug";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Lib "../src/lib";
import Utils "../src/utils";

actor class Test() = this {

    let sha512 = Lib.HmacSha512();
    
    private func hash(key: Lib.InputType, data: Lib.InputType): Text {
        
        sha512.init(key);
        
        sha512.update(data);
        
        let bytes = sha512.digest();
        Utils.bytesToHex(bytes);
    };

    private func multi_part_hash(key: Lib.InputType, data: [Lib.InputType]): Text {
        
        let sha512 = Lib.HmacSha512();
        sha512.init(key);
        for (part in data.vals()) {
            sha512.update(part);
        };
        sha512.hexdigest();
    };

    type TestCase = {
        keyHex: Text;
        messageHexParts: [Text];
        expectedDigestHex: ?Text; // Optional expected digest (null for now)
    };

    public func runTests() : async () {
        await suite("HMAC-SHA512", func() : async ()  {

            let tests: [TestCase] = [
                { keyHex = ""; messageHexParts = [""]; expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = [""]; expectedDigestHex = null },
                { keyHex = ""; messageHexParts = ["6d657373616765"]; expectedDigestHex = null },
                { keyHex = "6b"; messageHexParts = ["6d"]; expectedDigestHex = null },
                { keyHex = Text.join("", Array.tabulate<Text>(200, func _ = "41").vals()); messageHexParts = ["4869"]; expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = Array.tabulate<Text>(1000, func _ = "41"); expectedDigestHex = null },
                { keyHex = "736563726574"; messageHexParts = ["68", "65", "6c", "6c", "6f", "20", "77", "6f", "72", "6c", "64"]; expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = ["68656c", "6c6f20", "776f72", "6c64"]; expectedDigestHex = null },
                { keyHex = Text.join("", Array.tabulate<Text>(128, func _ = "aa").vals()); messageHexParts = ["48656c6c6f2c2053484135313221"]; expectedDigestHex = null },
                { keyHex = Text.join("", Array.tabulate<Text>(256, func _ = "bb").vals()); messageHexParts = ["48656c6c6f2c20576f726c6421"]; expectedDigestHex = null },
                { keyHex = "736563726574"; messageHexParts = ["61626300646566", "00676869"]; expectedDigestHex = null },
                { keyHex = Text.join("", Array.tabulate<Text>(16, func _ = "00").vals()); messageHexParts = ["6d657373616765"]; expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = ["f09f988af09f92bbf09f94a5"]; expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = ["68656c6c6f", "", "776f726c64", ""]; expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = Array.tabulate<Text>(100, func _ = "61626364"); expectedDigestHex = null },
                { keyHex = Text.join("", Array.tabulate<Text>(1024 * 4, func _ = "cc").vals()); messageHexParts = Array.tabulate<Text>(1024 * 4, func _ = "11"); expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = Array.tabulate<Text>(10, func _ = Text.join("", Array.tabulate<Text>(1024, func _ = "aa").vals())); expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = Array.flatten<Text>([["78"], Array.tabulate<Text>(2048, func _ = "ef"), ["79"], Array.tabulate<Text>(4096, func _ = "ee")]); expectedDigestHex = null },
                { keyHex = "6b6579"; messageHexParts = Array.tabulate<Text>(512, func _ = "00"); expectedDigestHex = null },
                { keyHex = Text.join("", Array.tabulate<Text>(1024 * 4, func _ = "dd").vals()); messageHexParts = Array.tabulate<Text>(1024 * 4, func _ = "22"); expectedDigestHex = null },
            ];

            let VECTORS = [
                {
                    key : Lib.InputType = #text "Jefe";
                    data : Lib.InputType  = #hex "7768617420646f2079612077616e7420666f72206e6f7468696e673f";
                    output = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
                },
                {
                    key : Lib.InputType  = #hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
                    data : Lib.InputType  = #hex "4869205468657265";
                    output = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
                },
                {
                    key : Lib.InputType   = #hex "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    data : Lib.InputType  = #hex "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
                    output = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
                },
                {
                    key : Lib.InputType   = #text "fun chest brief dignity card enable horn useless champion pool spirit borrow robust useless card capital deliver seek exotic hybrid scale artist rebuild cactus";
                    data : Lib.InputType  = #text "ability reduce away dizzy minute basic snake purity scheme better torch add cement vintage silk museum pulse brand crater toilet gym garment shuffle group";
                    output = "e474b346d68a0600c0f1a55459cc655d08ac6aa73fb29c33f3f5935ecb499be24ed7be9f602fe4327c95e3383263cb93caecf00d3a347bb1a036c57fd20a4814"
                },
                // Standard test from RFC 4231 - Test Case 4 (key > block size)
                {
                    key : Lib.InputType = #hex "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    data : Lib.InputType = #hex "54657374205573696e67204c61726765204b6579202d2048617368204b6579204669727374";
                    output = "f94246390484fee8f61a4c863eebf7d860b5a728367059d75295be96a62539cc6ffb280e158bae278c91696617cc177643679501c79b9545b64edf1f8fb8c393"
                },

                // Test Case 5 from RFC 4231 (key > block size, longer data)
                {
                    key : Lib.InputType = #hex "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    data : Lib.InputType = #hex "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e";
                    output = "ed842c5a56cfa84c1759d1ea22aa8c4e0948ffc92006a2b46fee9e4c5664f4334bca3c7a3b0aa02000dd806e713f5671a1a6ab1ff9ad8c0b74cf6fae94372a84"
                },

                // Empty key and message
                {
                    key : Lib.InputType = #hex "";
                    data : Lib.InputType = #hex "";
                    output = "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
                },

                // Very short key, long message
                {
                    key : Lib.InputType = #hex "0c";
                    data : Lib.InputType = #hex "5465737420576974682056657279204c6f6e67204d65737361676520546f205465737420486d61632d536861353132";
                    output = "478a0344ab04d99f98f971560010fade9346617a3f16c4ed9248aabb3412417e24b01f63c7aa8e3fb8e4c3159be3b8d9d274b17847da2cba595d70610330f66c"
                },

                // Binary key and message
                {
                    key : Lib.InputType = #hex "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
                    data : Lib.InputType = #hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
                    output = "05b9fdcc84446494edd336006ea2532794e72917dfb05ae1c34c414f303f0db7d48f8de779aa52964d0fce45d2e88e03e4e1d92fbeddfb10f004bef666c48227"
                }
            ];

            for (input in VECTORS.vals()) {
                await test("HMAC_SHA512 simple test", func(): async ()  {
                    let r = hash(input.key, input.data);
                    assert(r == input.output);
                });
            };

            for (input in tests.vals()) {
                let buf = Buffer.Buffer<Nat8>(0);
                for (part in input.messageHexParts.vals()) {
                    let partInput = Utils.hexToBytes(part);
                    buf.append(Buffer.fromArray(partInput));
                };
                await test("HMAC_SHA512 multi-part test | ", func(): async ()  {
                    let h1 = hash(#hex (input.keyHex), #bytes (Buffer.toArray(buf)));
                    let h2 = multi_part_hash(#hex (input.keyHex), Array.map<Text, Lib.InputType>(input.messageHexParts, func(part) = #hex part));
                    assert(h1 == h2);
                });
            };
        });
    };
}