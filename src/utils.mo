/*******************************************************************
* Copyright         : 2025 nirvana369
* File Name         : utils.mo
* Description       : Utilities
*                    
* Revision History  :
* Date				Author    		Comments
* ---------------------------------------------------------------------------
* 20/06/2025		nirvana369 		implement
******************************************************************/

import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Text "mo:base/Text";
import Char "mo:base/Char";
import Option "mo:base/Option";
import HashMap "mo:base/HashMap";
import Hash "mo:base/Hash";
import Int "mo:base/Int";
import Int32 "mo:base/Int32";

module Utils {

    func hexCharMap() : HashMap.HashMap<Nat, Nat8> {
        let map = HashMap.HashMap<Nat, Nat8>(16, Nat.equal, Hash.hash);
        for (n in Iter.range(48, 57)) { map.put(n, Nat8.fromNat(n - 48)); };
        for (n in Iter.range(97, 102)) { map.put(n, Nat8.fromNat(n - 87)); };
        for (n in Iter.range(65, 70)) { map.put(n, Nat8.fromNat(n - 55)); };
        map
    };

    func hexes() : [Text] {
        let symbols = Iter.toArray("0123456789abcdef".chars());
        Array.tabulate<Text>(256, func i : Text {
            let u8 = Nat8.fromNat(i);
            let high = Nat8.toNat(u8 / 16);
            let low = Nat8.toNat(u8 % 16);
            Char.toText(symbols[high]) # Char.toText(symbols[low])
        })
    };

    public func bytesToHex(uint8a: [Nat8]): Text {
        let hex = hexes();
        Array.foldLeft<Nat8, Text>(uint8a, "", func(acc, b) = acc # hex[Nat8.toNat(b)]);
    };

    public func hexToBytes(hex: Text): [Nat8] {
        let hexMap = hexCharMap();
        let chars = Iter.toArray(Text.toIter(hex));
        assert (chars.size() % 2 == 0);
        Array.tabulate<Nat8>(chars.size() / 2, func(i) {
            let hi = Option.get<Nat8>(hexMap.get(Nat32.toNat(Char.toNat32(chars[i*2]))), 0);
            let lo = Option.get<Nat8>(hexMap.get(Nat32.toNat(Char.toNat32(chars[i*2 + 1]))), 0);
            16 * hi + lo
        });
    };

    /// Converts a hexadecimal character to its integer value
    private func hexCharToInt(char: Char) : Int {
        switch char {
            case ('A' or 'a') 10;
            case ('B' or 'b') 11;
            case ('C' or 'c') 12;
            case ('D' or 'd') 13;
            case ('E' or 'e') 14;
            case ('F' or 'f') 15;
            case (c) Int32.toInt(Int32.fromNat32(Char.toNat32(c) - 48));
        }
    };

    /// Converts a hexadecimal string to its integer value
    public func hexToInt(hex: Text) : Int {
        var result : Int = 0;
        var length = hex.size();
        for (char in hex.chars()) {
            length -= 1;
            result += hexCharToInt(char) * (16 ** length);
        };
        result
    };
};
