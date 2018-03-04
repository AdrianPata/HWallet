package ro.pata.jc;

import javacard.framework.*;
import javacard.security.RandomData;
import javacard.security.Signature;

import static javacard.framework.ISO7816.OFFSET_CLA;
import static javacard.framework.ISO7816.OFFSET_INS;

public class HardwareWallet extends Applet {
    //Default authentication keys for pin "0000"
    //They are calculated using SHA256("0000"); the calculation is done on the client, on the smart card they are stored already calculated
    private static byte[] KP_ENC={(byte)0x9A, (byte)0xF1, (byte)0x5B, (byte)0x33, (byte)0x6E, (byte)0x6A, (byte)0x96, (byte)0x19, (byte)0x92, (byte)0x85, (byte)0x37, (byte)0xDF, (byte)0x30, (byte)0xB2, (byte)0xE6, (byte)0xA2}; //112 bit
    private static byte[] KP_MAC={(byte)0x37, (byte)0x65, (byte)0x69, (byte)0xFC, (byte)0xF9, (byte)0xD7, (byte)0xE7, (byte)0x73, (byte)0xEC, (byte)0xCE, (byte)0xDE, (byte)0x65, (byte)0x60, (byte)0x65, (byte)0x29, (byte)0xA0}; //112 bit

    //Instructions
    static final byte INS_GET_CHALLENGE = (byte) 0x84;
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
    static final byte INS_TEST=(byte) 0x01;
    static final byte INS_HELLO=(byte) 0x02;
    static final byte INS_RETRIES=(byte) 0x03;

    //Security
    private RandomData randomData;
    private byte[] rnd;
    private byte[] ssc;
    private PassportCrypto crypto;
    KeyStore keyStore;

    //Authentication retry
    //For each failed mutual authentication, the counter is decreased. If 0 is reached no other secure message is allowed (card is locked).
    static final byte AUTH_RETRIES=3;
    private byte authRetry=AUTH_RETRIES;

    static byte volatileState[];
    /* values for volatile state */
    static final byte CHALLENGED = 1;
    static final byte MUTUAL_AUTHENTICATED = 2; // ie BAC
    static final byte FILE_SELECTED = 4;
    static final byte CHIP_AUTHENTICATED = 0x10;
    static final byte TERMINAL_AUTHENTICATED = 0x20;

    //Constants
    static final byte CLA_PROTECTED_APDU = 0x0c;
    static final short RND_LENGTH = 8;
    static final short SW_INTERNAL_ERROR = (short) 0x6d66;
    static final short KEY_LENGTH = 16;
    static final short KEYMATERIAL_LENGTH = 16;
    static final short MAC_LENGTH = 8;
    private static final short SW_OK = (short) 0x9000;



    /**
     * Installs this applet.
     *
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HardwareWallet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected HardwareWallet() {
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        rnd = JCSystem.makeTransientByteArray(RND_LENGTH, JCSystem.CLEAR_ON_RESET);
        ssc = JCSystem.makeTransientByteArray((byte) 8, JCSystem.CLEAR_ON_RESET);

        //macK=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES3_2KEY, false);
        //encK=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES3_2KEY, false);
        //macK.setKey(KP_MAC, (short)0);
        //encK.setKey(KP_ENC, (short)0);

        //sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        //ciph = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);

        volatileState = JCSystem.makeTransientByteArray((byte) 1, JCSystem.CLEAR_ON_RESET);

        keyStore = new KeyStore(PassportCrypto.JCOP41_MODE);
        keyStore.setMutualAuthenticationKeys(KP_MAC,(short)0,KP_ENC,(short)0);
        crypto = new JCOP41PassportCrypto(keyStore);

        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];
        boolean protectedApdu = (byte)(cla & CLA_PROTECTED_APDU)  == CLA_PROTECTED_APDU;
        short responseLength = 0;
        short sw1sw2 = SW_OK;
        short le = 0;

        if(selectingApplet()) return;

        if (protectedApdu & hasMutuallyAuthenticated()) {
            try {
                le = crypto.unwrapCommandAPDU(ssc, apdu);
            } catch (CardRuntimeException e) {
                sw1sw2 = e.getReason();
            }
        } else if (protectedApdu) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        if (sw1sw2 == SW_OK) {
            try {
                responseLength = processAPDU(apdu, cla, ins, protectedApdu, le);
            } catch (CardRuntimeException e) {
                sw1sw2 = e.getReason();
            }
        }

        if (protectedApdu && hasMutuallyAuthenticated()) {
            responseLength = crypto.wrapResponseAPDU(ssc, apdu, (short)0, responseLength, sw1sw2);
        }

        if (responseLength > 0) {
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING)
                apdu.setOutgoing();
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING_LENGTH_KNOWN)
                apdu.setOutgoingLength(responseLength);
            apdu.sendBytes((short) 0, responseLength);
        }

        if (sw1sw2 != SW_OK) {
            ISOException.throwIt(sw1sw2);
        }
    }

    public short processAPDU(APDU apdu, byte cla, byte ins, boolean protectedApdu, short le) {
        short responseLength = 0;

        switch(ins){
            case INS_GET_CHALLENGE:
                responseLength=insGetChallenge(apdu);
                break;
            case INS_EXTERNAL_AUTHENTICATE:
                responseLength= insMutualAuthenticate(apdu);
                break;
            case INS_TEST:
                responseLength=insTest(apdu);
                break;
            case INS_HELLO:
                responseLength= insHello(apdu);
                break;
            case INS_RETRIES:
                responseLength=insRetries(apdu);
                break;
        }

        return responseLength;
    }

    public void process_bak(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];
        boolean protectedApdu = (byte)(cla & CLA_PROTECTED_APDU)  == CLA_PROTECTED_APDU;
        short responseLength = 0;

        if(selectingApplet()) return;

        switch(ins){
            case INS_GET_CHALLENGE:
                responseLength=insGetChallenge(apdu);
                break;
            case INS_EXTERNAL_AUTHENTICATE:
                responseLength= insMutualAuthenticate(apdu);
                break;
        }

        if (responseLength > 0) {
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING)
                apdu.setOutgoing();
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING_LENGTH_KNOWN)
                apdu.setOutgoingLength(responseLength);
            apdu.sendBytes((short) 0, responseLength);
        }
    }

    private short insGetChallenge(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        randomData.generateData(rnd, (short) 0, (byte)0x08);
        Util.arrayCopyNonAtomic(rnd, (short) 0, buffer, (short)0x00, (short)0x08);
        volatileState[0] |= CHALLENGED;
        return (short)0x08;
    }

    private short insMutualAuthenticate(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        short e_ifd_length = RND_LENGTH + RND_LENGTH + KEYMATERIAL_LENGTH;

        if (bytesLeft != (short) (e_ifd_length + MAC_LENGTH)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short e_ifd_p = ISO7816.OFFSET_CDATA;
        short m_ifd_p = (short) (e_ifd_p + e_ifd_length);

        //Verify retry counter
        if(authRetry==0){
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        //verify MAC and decrease counter in case of verify fail
        crypto.initMac(Signature.MODE_VERIFY);
        if(!crypto.verifyMacFinal(buffer, e_ifd_p, e_ifd_length, buffer, m_ifd_p)) {
            if(authRetry>0) authRetry--;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        //If the authentication was successful, reset the retry counter
        if(authRetry<AUTH_RETRIES) authRetry=AUTH_RETRIES;

        // decrypt e_ifd into buffer[0] where buffer = rnd.ifd || rnd.icc || k.ifd
        crypto.decryptInit();
        short plaintext_len = crypto.decryptFinal(buffer, e_ifd_p, e_ifd_length, buffer, (short) 0);
        if (plaintext_len != e_ifd_length) ISOException.throwIt(SW_INTERNAL_ERROR); // sanity check

        short rnd_ifd_p = 0;
        short rnd_icc_p = RND_LENGTH;
        short k_ifd_p = (short) (rnd_icc_p + RND_LENGTH);

        /*
         * we use apdu buffer for writing intermediate data in buffer with
         * following pointers
         */
        short k_icc_p = (short) (k_ifd_p + KEYMATERIAL_LENGTH);
        short keySeed_p = (short) (k_icc_p + KEYMATERIAL_LENGTH);
        short keys_p = (short) (keySeed_p + KEYMATERIAL_LENGTH);

        // verify that rnd.icc equals value generated in getChallenge
        if (Util.arrayCompare(buffer, rnd_icc_p, rnd, (short) 0, RND_LENGTH) != 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        // generate keying material k.icc
        randomData.generateData(buffer, k_icc_p, KEYMATERIAL_LENGTH);

        // calculate keySeed for session keys by xorring k_ifd and k_icc
        PassportUtil.xor(buffer, k_ifd_p, buffer, k_icc_p, buffer, keySeed_p, KEYMATERIAL_LENGTH);

        // calculate session keys
        crypto.deriveKey(buffer, keySeed_p, KEYMATERIAL_LENGTH, PassportCrypto.MAC_MODE, keys_p);
        short macKey_p = keys_p;
        keys_p += KEY_LENGTH;
        crypto.deriveKey(buffer, keySeed_p, KEYMATERIAL_LENGTH, PassportCrypto.ENC_MODE, keys_p);
        short encKey_p = keys_p;
        keys_p += KEY_LENGTH;
        keyStore.setSecureMessagingKeys(buffer, macKey_p, buffer, encKey_p);

        // compute ssc
        PassportCrypto.computeSSC(buffer, rnd_icc_p, buffer, rnd_ifd_p, ssc);

        // create response in buffer where response = rnd.icc || rnd.ifd ||
        // k.icc
        PassportUtil.swap(buffer, rnd_icc_p, rnd_ifd_p, RND_LENGTH);
        Util.arrayCopyNonAtomic(buffer, k_icc_p, buffer, (short) (2 * RND_LENGTH), KEYMATERIAL_LENGTH);

        // make buffer encrypted using k_enc
        crypto.encryptInit();
        short ciphertext_len = crypto.encryptFinal(buffer, (short) 0, (short) (2 * RND_LENGTH + KEYMATERIAL_LENGTH), buffer, (short) 0);

        // create m_icc which is a checksum of response
        crypto.initMac(Signature.MODE_SIGN);
        crypto.createMacFinal(buffer, (short) 0, ciphertext_len, buffer, ciphertext_len);


        setNoChallenged();
        volatileState[0] |= MUTUAL_AUTHENTICATED;

        return (short) (ciphertext_len + MAC_LENGTH);
    }

    private short insTest(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        byte[] data="Adi".getBytes();
        Util.arrayCopyNonAtomic(data,(short)0,buffer,(short)0,(short)3);
        return 3;
    }

    /**
     * The function is used to verify the applet. If it returns 'Hello' the applet is fine.
     * @param apdu
     * @return
     */
    private short insHello(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        byte[] response={'H','e','l','l','o'};
        Util.arrayCopyNonAtomic(response,(short)0,buffer,(short)0,(short)response.length);
        return (short)response.length;
    }

    /**
     * Return the remaining retries for authentication. If they are 0 the card is locked.
     * @param apdu
     * @return
     */
    private short insRetries(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        buffer[0]=authRetry;
        return (short)1;
    }

    /** Has BAC been completed? */
    public static boolean hasMutuallyAuthenticated() {
        return (volatileState[0] & MUTUAL_AUTHENTICATED) == MUTUAL_AUTHENTICATED;
    }

    public static void setNoChallenged() {
        if ((volatileState[0] & CHALLENGED) == CHALLENGED) {
            volatileState[0] ^= CHALLENGED;
        }
    }
}
