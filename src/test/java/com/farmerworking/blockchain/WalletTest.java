package com.farmerworking.blockchain;

import java.util.Arrays;

import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;

/**
 * Created by John on 18/3/9.
 */
public class WalletTest extends TestCase {
    public void testGenerateWords() throws Exception {
        String[] words = Wallet.generateWords(null);
        assert words.length == 24;
    }

    public void testGenerateWords2() throws Exception {
        String[] words = Wallet.generateWords("2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c");
        assert words.length == 24;
        assertEquals(String.join(" ", Arrays.asList(words)), "cake apple borrow silk endorse fitness top denial coil " +
            "riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige");

        String seedHex = Hex.encodeHexString(Wallet.toSeed("", words));
        assertEquals(seedHex, "3269bce2674acbd188d4f120072b13b088a0ecf87c6e4cae41657a0bb78f5315b33b3a04356e53d062e5" +
            "5f1e0deaa082df8d487381379df848a6ad7e98798404");
    }
}