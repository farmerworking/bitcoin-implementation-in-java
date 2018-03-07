package com.farmerworking.blockchain;

import junit.framework.TestCase;

/**
 * Created by John on 18/3/6.
 */
public class PrivateKeyTest extends TestCase {
    public void testPrivateKeyTransform1() throws Exception {
        PrivateKey privateKey = PrivateKey.fromWIFCompressed("KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ");
        assertEquals(privateKey.toWIFCompressed(), "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ");
        assertEquals(privateKey.toHex(), "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd");
        assertEquals(privateKey.toWIF(), "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn");
    }

    public void testPrivateKeyTransform2() throws Exception {
        PrivateKey privateKey = PrivateKey.fromHex("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd");
        assertEquals(privateKey.toWIFCompressed(), "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ");
        assertEquals(privateKey.toHex(), "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd");
        assertEquals(privateKey.toWIF(), "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn");
    }

    public void testPrivateKeyTransform3() throws Exception {
        PrivateKey privateKey = PrivateKey.fromWIF("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn");
        assertEquals(privateKey.toWIFCompressed(), "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ");
        assertEquals(privateKey.toHex(), "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd");
        assertEquals(privateKey.toWIF(), "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn");
    }

    public void testPrivateKey2PublicKey1() throws Exception {
        PrivateKey privateKey = PrivateKey.fromWIFCompressed("KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S");
        PublicKey publicKey = privateKey.getPublicKey();


        assertEquals(publicKey.toHex(), "025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec");
        assertEquals(publicKey.getBitcoinAddress(), "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3");
    }

    public void testPrivateKey2PublicKey2() throws Exception {
        PrivateKey privateKey = PrivateKey.fromWIF("5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K");
        PublicKey publicKey = privateKey.getPublicKey();

        assertEquals(publicKey.toHex(), "045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176");
        assertEquals(publicKey.getBitcoinAddress(), "1thMirt546nngXqyPEz532S8fLwbozud8");
    }

    /** use www.bitaddress.org wallet details to validate*/
    public void testPrivateKeyGenerate() throws Exception {
        PrivateKey privateKey = PrivateKey.generate();
        System.out.println(privateKey.toHex());
        System.out.println(privateKey.toWIFCompressed());
        System.out.println(privateKey.toWIF());

        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println(publicKey.toHex());
        System.out.println(publicKey.getBitcoinAddress());
    }
}