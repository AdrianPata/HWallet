/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import java.math.BigInteger;
import javax.annotation.Nullable;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoinj.core.ECKey;
import static org.bitcoinj.core.ECKey.CURVE;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.TransactionSignature;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;

/**
 *
 * @author adi
 */
public class ECKeyHW extends ECKey {
    private byte[] dataToSign;
    
    public ECKeyHW(ECKey k){
        super(k.getPrivKeyBytes(),k.getPubKey());
    }
    
    @Override
    public ECDSASignature sign(Sha256Hash input) throws KeyCrypterException {
        return sign(input, null);
    }
    
    @Override
    public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        return doSign(input, priv);
    }
    
    @Override
    protected ECDSASignature doSign(Sha256Hash input, BigInteger privateKeyForSigning) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(input.getBytes());
        return new ECDSASignature(components[0], components[1]).toCanonicalised();
    }       
}
