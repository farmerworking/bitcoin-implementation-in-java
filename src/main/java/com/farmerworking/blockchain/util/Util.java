package com.farmerworking.blockchain.util;

import java.util.Arrays;

import com.google.common.primitives.Bytes;
import org.apache.commons.codec.digest.DigestUtils;
import org.bitcoinj.core.Base58;
import org.spongycastle.crypto.digests.RIPEMD160Digest;

public class Util {
    public static byte[] doubleSha256(byte[] input) {
        return DigestUtils.sha256(DigestUtils.sha256(input));
    }

    public static byte[] checksum(byte[] payload) {
        return Arrays.copyOf(Util.doubleSha256(payload), 4);
    }

    public static byte[] sha256Ripemd160(byte[] payload) {
        byte[] sha256 = DigestUtils.sha256(payload);
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256, 0, sha256.length);
        byte[] result = new byte[20];
        digest.doFinal(result, 0);
        return result;
    }

    public static String base58CheckEncode(byte[]...arrays) {
        byte[] checksum = Util.checksum(Bytes.concat(arrays));
        return Base58.encode(Bytes.concat(Bytes.concat(arrays), checksum));
    }

    public static String toBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * Byte.SIZE);
        for( int i = 0; i < Byte.SIZE * bytes.length; i++ )
            sb.append((bytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
        return sb.toString();
    }
}
