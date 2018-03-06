package com.farmerworking.blockchain;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import com.farmerworking.blockchain.util.Util;
import lombok.Data;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bitcoin.NativeSecp256k1Util.AssertFailException;
import org.bitcoinj.core.Base58;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;
import org.spongycastle.math.ec.WNafUtil;

@Data
public class PrivateKey {
    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /** The parameters of the secp256k1 curve that Bitcoin uses. */
    public static final ECDomainParameters CURVE = new ECDomainParameters(
        CURVE_PARAMS.getCurve(),
        CURVE_PARAMS.getG(),
        CURVE_PARAMS.getN(),
        CURVE_PARAMS.getH());

    public static final Integer BITS_OF_ENTROPY_LENGTH = 256;

    private byte[] privateKey;
    private final Boolean compressed;

    public PrivateKey(byte[] privateKey, Boolean compressed) {
        this.privateKey = privateKey;
        this.compressed = compressed;
    }

    public String toWIF() {
        return Util.base58CheckEncode(
            new byte[]{PrefixConstant.PRIVATE_KEY_PREFIX.byteValue()},
            privateKey
        );
    }

    public static PrivateKey fromWIF(String wif) {
        assert wif.length() == 51;
        byte[] versionAndPayload = Base58.decodeChecked(wif);
        int version = versionAndPayload[0] & 0xFF;
        byte[] payload = Arrays.copyOfRange(versionAndPayload, 1, versionAndPayload.length);
        assert version == PrefixConstant.PRIVATE_KEY_PREFIX;
        return new PrivateKey(Arrays.copyOf(payload, payload.length), false);
    }

    public String toWIFCompressed() {
        return Util.base58CheckEncode(
            new byte[]{PrefixConstant.PRIVATE_KEY_PREFIX.byteValue()},
            privateKey,
            new byte[]{SuffixConstant.WIF_COMPRESSED_SUFFIX.byteValue()}
        );
    }

    public static PrivateKey fromWIFCompressed(String wifCompressed) {
        assert wifCompressed.length() == 52;
        byte[] versionAndPayload = Base58.decodeChecked(wifCompressed);
        int version = versionAndPayload[0] & 0xFF;
        byte[] payload = Arrays.copyOfRange(versionAndPayload, 1, versionAndPayload.length);
        assert version == PrefixConstant.PRIVATE_KEY_PREFIX;
        return new PrivateKey(Arrays.copyOf(payload, payload.length - 1), true);
    }

    public String toHex() {
        return Hex.encodeHexString(privateKey);
    }

    public static PrivateKey fromHex(String hex) throws DecoderException {
        return new PrivateKey(Hex.decodeHex(hex.toCharArray()), false);
    }

    public static synchronized PrivateKey generate() throws AssertFailException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomSource = secureRandom.generateSeed(BITS_OF_ENTROPY_LENGTH);
        byte[] bytes = DigestUtils.sha256(randomSource);
        BigInteger d = new BigInteger(bytes);
        int minWeight = CURVE.getN().bitLength() >>> 2;

        if (d.compareTo(BigInteger.valueOf(2)) < 0  || (d.compareTo(CURVE.getN()) >= 0))
        {
            return generate();
        }

        if (WNafUtil.getNafWeight(d) < minWeight)
        {
            return generate();
        }

        return new PrivateKey(bytes, true);
    }

    public PublicKey getPublicKey() {
        BigInteger privKey = new BigInteger(privateKey);

        if (privKey.bitLength() > CURVE.getN().bitLength()) {
            privKey = privKey.mod(CURVE.getN());
        }

        ECPoint point = new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
        return new PublicKey(point, compressed);
    }
}
