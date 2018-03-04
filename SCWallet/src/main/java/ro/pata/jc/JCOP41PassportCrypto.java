package ro.pata.jc;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/***
 * Class that implements creation signatures of ALG_DES_MAC8_ISO9797_M2_ALG3
 * using ALG_DES_MAC8_ISO9797_M2.
 *
 * @author ceesb
 *
 */public class JCOP41PassportCrypto extends PassportCrypto {
    private Cipher macCiphECB;
    private byte[] tempSpace_verifyMac;

    JCOP41PassportCrypto(KeyStore keyStore) {
        super(keyStore);

        tempSpace_verifyMac = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
    }

    protected void init() {
        ciph = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);

        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2,
                false);

        macCiphECB = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);

    }

    public void initMac(byte mode) {
        DESKey k = keyStore.getMacKey(KeyStore.KEY_A);

        sig.init(k, Signature.MODE_SIGN);
    }

    public void createMacFinal(byte[] msg, short msg_offset, short msg_len,
                               byte[] mac, short mac_offset) {
        DESKey kA = keyStore.getMacKey(KeyStore.KEY_A);
        DESKey kB = keyStore.getMacKey(KeyStore.KEY_B);

        sig.sign(msg, msg_offset, msg_len, mac, mac_offset);

        macCiphECB.init(kB, Cipher.MODE_DECRYPT);
        macCiphECB.doFinal(mac, mac_offset, (short)8, mac, mac_offset);

        macCiphECB.init(kA, Cipher.MODE_ENCRYPT);
        macCiphECB.doFinal(mac, mac_offset, (short)8, mac, mac_offset);
    }


    public boolean verifyMacFinal(byte[] msg, short msg_offset, short msg_len,
                                  byte[] mac, short mac_offset) {

        createMacFinal(msg, msg_offset, msg_len, tempSpace_verifyMac, (short)0);

        if(Util.arrayCompare(mac, mac_offset, tempSpace_verifyMac, (short)0, (short)8) == 0) {
            return true;
        }
        return false;
    }
}

