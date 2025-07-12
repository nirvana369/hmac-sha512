/*******************************************************************
* Copyright         : 2025 nirvana369
* File Name         : hmac.bench.mo
* Description       : Benchmark hmac-sha512.
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 12/07/2025		nirvana369 		Add benchmarks.
******************************************************************/

import Bench "mo:bench";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";
import Lib "../src/lib";
import Text "mo:base/Text";

module {

    private func hash(key: Lib.InputType, data: Lib.InputType): Text {
        
        let sha512 = Lib.HmacSha512();
        sha512.init(key);
        
        sha512.update(data);
        
        sha512.hexdigest();
    };

    public func init() : Bench.Bench {

        let test = {
                    key : Lib.InputType = #hex "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
                    data : Lib.InputType = #hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
                    output = "05b9fdcc84446494edd336006ea2532794e72917dfb05ae1c34c414f303f0db7d48f8de779aa52964d0fce45d2e88e03e4e1d92fbeddfb10f004bef666c48227"
                };
        let bench = Bench.Bench();

        bench.name("HMAC-SHA512 Benchmark");
        bench.description("PBKDF2 module benchmark");

        bench.rows(["hmac_sha512",
                    ]);
        bench.cols(["1", "100", "500", "1000", "5000"]);

        bench.runner(func(row, col) {
            let ?n = Nat.fromText(col);

            switch (row) {
                // Engine V1
                case ("hmac_sha512") {
                    for (i in Iter.range(1, n)) {
                        ignore hash(test.key, test.data);
                    };
                };
                case _ {};
            };
        });

        bench;
  };
};