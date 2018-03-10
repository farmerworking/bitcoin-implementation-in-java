package com.farmerworking.blockchain;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;

import com.farmerworking.blockchain.util.Util;
import com.google.common.base.Splitter;
import com.google.common.primitives.Bytes;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bitcoinj.crypto.PBKDF2SHA512;

public class Wallet {
    public static final Integer DEFAULT_ENTROPY_LENGTH_IN_BITS = 256;

    public static final String SALT_PREFIX = "mnemonic";

    public static String[] generateWords(String entropyHex) throws DecoderException {
        String[] result = new String[24];

        byte[] entropyWithChecksum = getEntropyWithChecksum(entropyHex);

        String binary = Util.toBinary(entropyWithChecksum);
        assert (binary.length() % 11) == 0;

        Iterator<String> keyList = Splitter.fixedLength(11).split(binary).iterator();
        int index = 0;
        while(keyList.hasNext()) {
            result[index ++] = WalletDictionary.dictionary.get(Integer.parseInt(keyList.next(), 2));
        }

        return result;
    }

    public static byte[] toSeed(String passphrase, String[] input) {
        String pass = String.join(" ", Arrays.asList(input));
        return PBKDF2SHA512.derive(pass, SALT_PREFIX + passphrase, 2048, 64);
    }

    private static byte[] getEntropyWithChecksum(String entropyHex) throws DecoderException {
        byte[] entropy = entropyHex == null ? getEntropy() : Hex.decodeHex(entropyHex.toCharArray());
        byte[] checksum = getChecksum(entropy);
        return Bytes.concat(entropy, checksum);
    }

    private static byte[] getChecksum(byte[] tmp) {
        int checksumLengthInByte = DEFAULT_ENTROPY_LENGTH_IN_BITS / 32 / 8;
        byte[] sha256 = DigestUtils.sha256(tmp);
        return Arrays.copyOf(sha256, checksumLengthInByte);
    }

    private static byte[] getEntropy() {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.generateSeed(DEFAULT_ENTROPY_LENGTH_IN_BITS / 8);
    }
}
