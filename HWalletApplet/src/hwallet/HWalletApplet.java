/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package hwallet;

import static hwallet.Secp256k1.ALG_EC_SVDP_DH_PLAIN;
import static hwallet.Secp256k1.ALG_EC_SVDP_DH_PLAIN_XY;
import javacard.framework.*;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
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
    private final static byte INS_KEY_CREATE=(byte)0x01;
    
    private final static byte INS_PUB_KEY=(byte)0x02;
    private final static byte INS_PRIV_KEY=(byte)0x03;
    private final static byte INS_HASH=(byte)0x04;
    private final static byte INS_SET_PRIV_KEY=(byte)0x05;
    private final static byte INS_SET_PUB_KEY=(byte)0x06;
    private final static byte INS_SIGN=(byte)0x07;
    private static final byte INS_REGISTERED_KEYS=(byte)0x08;
    
    private final static byte TOTAL_KEYS=10;
    private byte registeredKeys=0;
    private KeyPair[] keys;
    private RandomData randomData;
    protected static KeyPair keyPair;
    private MessageDigest sha256;
    protected static Signature signature;
    private KeyAgreement keyAgreement;
    
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
        keys = new KeyPair[TOTAL_KEYS];
        sha256=MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false); 
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
                apdu.setOutgoingAndSend((short)0, (short)3);
                break;
            case INS_KEY_CREATE:
                keyCreate(buffer);
                //Return created key number
                apdu.setOutgoingAndSend((short)0, (short)1); 
                break;
            case INS_PUB_KEY:
                size=(short)(getPubKey(buffer));
                apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_PRIV_KEY:
                size=(short)(getPrivKey(buffer));
                apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_HASH:
                size=getHash(buffer);
                apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_SET_PRIV_KEY:
                size=setPrivKey(buffer);
                //apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_SET_PUB_KEY:
                size=setPubKey(buffer);
                //apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_SIGN:
                size=getSignature(buffer);
                apdu.setOutgoingAndSend((short)0, size);
                break;
            case INS_REGISTERED_KEYS:
                size=getRegisteredKeys(buffer);
                apdu.setOutgoingAndSend((short)0, size);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        
        
    }
    
    private void getKeyStatus(byte[] buffer){
        byte p1=buffer[ISO7816.OFFSET_P1];
        byte p2=buffer[ISO7816.OFFSET_P2];
        
        if(keyPair==null){
            buffer[0]=0x01;
        } else {
            buffer[0]=0x02;
        }   
        
        if(p1==(byte)0xEE) {
            buffer[1]=(byte)0xAA;
        } else {
            buffer[1]=(byte)0xFF;
        }
        buffer[2]=p1;
    }
    
    private void keyCreate(byte[] buffer){
        if(registeredKeys<TOTAL_KEYS){
            keys[registeredKeys] = new KeyPair(
                            (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                            (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
                    Secp256k1.setCommonCurveParameters((ECKey)keys[registeredKeys].getPrivate());
                    Secp256k1.setCommonCurveParameters((ECKey)keys[registeredKeys].getPublic());

            //Generate the key pair only if P1 == 0x01
            if(buffer[ISO7816.OFFSET_P1]==(byte)0x01){        
                keys[registeredKeys].genKeyPair();
            } 
            
            //Return current key number
            buffer[0]=registeredKeys;
            
            registeredKeys++;           
        } else {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
    }
    
    private short getPubKey(byte[] buffer){
        byte p1=buffer[ISO7816.OFFSET_P1];
        if(p1>=registeredKeys){
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        
        ECPublicKey pub=(ECPublicKey)keys[p1].getPublic();        
        return pub.getW(buffer, (short)0);
    }
    
    private short getPrivKey(byte[] buffer){
        ECPrivateKey priv=(ECPrivateKey)keyPair.getPrivate();
        
        short size=priv.getS(buffer, (short)0);
        //buffer[1] = (byte)(size & 0xff);
        //buffer[0] = (byte)((size >> 8) & 0xff);
        
        return size;
    }
    
    private short getHash(byte[] buffer){
        short size=sha256.doFinal(msg, (short)0, (short)3, buffer, (short)0);
        
        signature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        size=signature.sign(msg, (short)0, (short)3, buffer, (short)0);
        
        return size;
    }
    
    private short getSignature(byte[] buffer){
        byte keyNumber=buffer[ISO7816.OFFSET_P1];
        signature.init(keys[keyNumber].getPrivate(), Signature.MODE_SIGN);        
        short size=signature.sign(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], buffer, (short)0);        
        return size;
    }
    
    private short setPrivKey(byte[] buffer){
        byte keyNumber=buffer[ISO7816.OFFSET_P1];        
        ECPrivateKey priv=(ECPrivateKey)keys[keyNumber].getPrivate();
        priv.setS(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);
        //keyAgreement.init(priv);
        //short coordx_size = keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)0); // compute x coordinate of public key as k*G
        return 0;
    }
    
    private short setPubKey(byte[] buffer){
        byte keyNumber=buffer[ISO7816.OFFSET_P1]; 
        ECPublicKey pub=(ECPublicKey)keys[keyNumber].getPublic();
        pub.setW(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC]);
        return 0;
    }
    
    private short getRegisteredKeys(byte[] buffer){
        buffer[0]=registeredKeys; 
        return 1;
    }
    
    private void initKeysOld(byte[] recvBuffer){
        //keys[0]=KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_128, false);
        //ECPrivateKey prv_key = (ECPrivateKey)keys[0];
        //Secp256k1.setCommonCurveParameters(prv_key);
        //if(randomData==null) randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        //randomData.generateData(recvBuffer,(short)0,(short)(KeyBuilder.LENGTH_EC_FP_256/8));
        //prv_key.setS(recvBuffer, (short)0, (short)(KeyBuilder.LENGTH_EC_FP_256/8));
        //Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)(KeyBuilder.LENGTH_EC_FP_256/8), (byte)0);
    }
}
