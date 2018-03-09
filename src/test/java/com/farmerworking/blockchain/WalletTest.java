package com.farmerworking.blockchain;

import junit.framework.TestCase;

/**
 * Created by John on 18/3/9.
 */
public class WalletTest extends TestCase {
    public void testGenerateWords() throws Exception {
        String[] words = Wallet.generateWords(null);
        assert words.length == 24;
    }
    }
}