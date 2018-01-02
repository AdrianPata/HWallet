/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import javax.annotation.Nullable;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.crypto.KeyCrypterException;
import org.spongycastle.crypto.params.KeyParameter;

/**
 *
 * @author adi
 */
public class ECKeyHW extends ECKey {
    @Override
    public ECDSASignature sign(Sha256Hash input) throws KeyCrypterException {
        return sign(input, null);
    }
    
    public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        return doSign(input, priv);
    }
}
