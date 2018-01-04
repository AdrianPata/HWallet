/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package hwallet;

import javacard.framework.*;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;

/**
 *
 * @author 10051644
 */
public class HWalletApplet extends Applet {

    private final static byte CLS=(byte)0x80;
    private final static byte INS_KEY_STATUS=(byte)0x00;
    private final static byte INS_INIT=(byte)0x01;
    
    private final static byte INS_PUB_KEY=(byte)0x02;
    private final static byte INS_PRIV_KEY=(byte)0x03;
    private final static byte INS_HASH=(byte)0x04;
    
    private Key[] keys;
    private RandomData randomData;
    protected static KeyPair keyPair;
    private MessageDigest sha256;
    protected static Signature signature;
    
    private byte[] msg={0x41,0x44,0x49};
    public static byte[] scratch256;
    
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
        new HWalletApplet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected HWalletApplet() {
        keys = new Key[0x0A];
        sha256=MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
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
        if (selectingApplet()) return;
        byte[] buffer=apdu.getBuffer();
        if(buffer[ISO7816.OFFSET_CLA]!=CLS) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        
        short size;
        
        switch(buffer[ISO7816.OFFSET_INS]){
            case INS_KEY_STATUS:
                getKeyStatus(buffer);
                apdu.setOutgoingAndSend((short)0, (short)1);
                break;
            case INS_INIT:
                initKeys2();
                break;
            case INS_PUB_KEY:
                size=(short)(getPubKey(buffer)+2);
                apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_PRIV_KEY:
                size=(short)(getPrivKey(buffer)+2);
                apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_HASH:
                size=getHash(buffer);
                apdu.setOutgoingAndSend((short)0, size);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        
        
    }
    
    private void getKeyStatus(byte[] buffer){
        if(keyPair==null){
            buffer[0]=0x01;
        } else {
            buffer[0]=0x02;
        }        
    }
    
    private void initKeys2(){
        keyPair = new KeyPair(
                        (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                        (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
                Secp256k1.setCommonCurveParameters((ECKey)keyPair.getPrivate());
                Secp256k1.setCommonCurveParameters((ECKey)keyPair.getPublic());
        
                keyPair.genKeyPair();
    }
    
    private short getPubKey(byte[] buffer){
        ECPublicKey pub=(ECPublicKey)keyPair.getPublic();
        
        short size=pub.getW(buffer, (short)2);
        
        buffer[1] = (byte)(size & 0xff);
        buffer[0] = (byte)((size >> 8) & 0xff);
        
        return size;
    }
    
    private short getPrivKey(byte[] buffer){
        ECPrivateKey priv=(ECPrivateKey)keyPair.getPrivate();
        
        short size=priv.getS(buffer, (short)2);
        buffer[1] = (byte)(size & 0xff);
        buffer[0] = (byte)((size >> 8) & 0xff);
        
        return size;
    }
    
    private short getHash(byte[] buffer){
        short size=sha256.doFinal(msg, (short)0, (short)3, buffer, (short)0);
        
        signature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        size=signature.sign(msg, (short)0, (short)3, buffer, (short)0);
        
        return size;
    }
    
    private void initKeys(byte[] recvBuffer){
        keys[0]=KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_128, false);
        ECPrivateKey prv_key = (ECPrivateKey)keys[0];
        //Secp256k1.setCommonCurveParameters(prv_key);
        if(randomData==null) randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        randomData.generateData(recvBuffer,(short)0,(short)(KeyBuilder.LENGTH_EC_FP_256/8));
        //prv_key.setS(recvBuffer, (short)0, (short)(KeyBuilder.LENGTH_EC_FP_256/8));
        Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)(KeyBuilder.LENGTH_EC_FP_256/8), (byte)0);
    }
}
