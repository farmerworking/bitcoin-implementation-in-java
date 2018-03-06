package com.farmerworking.blockchain;

import com.farmerworking.blockchain.util.Util;
import lombok.Data;
import org.apache.commons.codec.binary.Hex;
import org.spongycastle.math.ec.ECPoint;

@Data
public class PublicKey {
    private ECPoint point;
    private byte[] publicKey;
    private final Boolean compressed;

    public PublicKey(ECPoint point, Boolean compressed) {
        this.point = point;
        this.compressed = compressed;
        this.publicKey = this.point.getEncoded(this.compressed);
    }

    private byte[] getPublicKeyHash() {
        return Util.sha256Ripemd160(publicKey);
    }

    public String getBitcoinAddress() {
        byte[] publicKeyHash = getPublicKeyHash();
        byte[] version = new byte[] {PrefixConstant.BITCOIN_ADDRESS_PREFIX.byteValue()};

        return Util.base58CheckEncode(version, publicKeyHash);
    }

    public String toHex() {
        return Hex.encodeHexString(publicKey);
    }
}
