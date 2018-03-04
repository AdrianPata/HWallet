package ro.pata.bitcoin.client;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ro.pata.bitcoin.client.crypto.*;
import ro.pata.jc.HardwareWallet;

import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class SmartCardController implements SmartCardInterface {
    private SecureRandom random;
    //Aceste chei au 192 biti, dar in realitate ultima este la fel cu prima deoarece Boncy Castle nu suporta 3DES cu doua chei
    private byte[] KP_ENC={(byte)0x8f, (byte)0xc9, (byte)0xfe, (byte)0xae, (byte)0x1a, (byte)0xdd, (byte)0x23, (byte)0x39, (byte)0xc1, (byte)0x8a, (byte)0x99, (byte)0x4e, (byte)0x74, (byte)0xd1, (byte)0x18, (byte)0xc1, (byte)0x8f, (byte)0xc9, (byte)0xfe, (byte)0xae, (byte)0x1a, (byte)0xdd, (byte)0x23, (byte)0x39};
    private byte[] KP_MAC={(byte)0xb7, (byte)0xa1, (byte)0x7f, (byte)0xa0, (byte)0x54, (byte)0x03, (byte)0x3c, (byte)0xe7, (byte)0x9f, (byte)0x92, (byte)0xc2, (byte)0xf4, (byte)0xcf, (byte)0xc7, (byte)0x98, (byte)0x9a, (byte)0xb7, (byte)0xa1, (byte)0x7f, (byte)0xa0, (byte)0x54, (byte)0x03, (byte)0x3c, (byte)0xe7};

    private byte[] rndicc; //Random from chip
    private byte[] rndifd={(byte)0x8A, (byte)0x9E, (byte)0x4B, (byte)0x90, (byte)0x53, (byte)0xE6, (byte)0xC0, (byte)0x9B}; //Random from terminal
    private byte[] kifd={(byte)0x47, (byte)0xb5, (byte)0x46, (byte)0xcc, (byte)0x1b, (byte)0xd0, (byte)0xc3, (byte)0x20, (byte)0x97, (byte)0xcd, (byte)0x0d, (byte)0x78, (byte)0x23, (byte)0x50, (byte)0xe0, (byte)0x4e}; //Key from terminal
    private byte[] kicc={(byte)0x88, (byte)0xea, (byte)0x99, (byte)0xbc, (byte)0xc4, (byte)0x70, (byte)0x2c, (byte)0x52, (byte)0xc4, (byte)0x6f, (byte)0x48, (byte)0x3f, (byte)0x5e, (byte)0xc6, (byte)0xed, (byte)0x84}; //Key from chip
    private byte[] iv=new byte[8];
    private SecretKeySpec kenc; //Session key
    private SecretKeySpec kmac; //Session key
    private byte[] ssc=new byte[8]; //Send Sequence Counter

    private JavaxSmartCardInterface simulator;
    private AID aid;

    private boolean secureMessaging=false;

    public void init(){
        Security.addProvider(new BouncyCastleProvider());

        //BC is the ID for the Bouncy Castle provider;
        if (Security.getProvider("BC") == null){
            System.out.println("Bouncy Castle provider is NOT available");
        }
        else{
            System.out.println("Bouncy Castle provider is available");
        }

        simulator = new JavaxSmartCardInterface();
        byte[] aidb={(byte)0X14, (byte)0X36, (byte)0X57, (byte)0X02, (byte)0X0D, (byte)0XDF};
        aid=new AID(aidb,(byte)0,(byte)6);
        simulator.installApplet(aid, HardwareWallet.class);

        Crypto.init_test();
    }

    public void selectApp() throws JCException {
        simulator.selectApplet(aid);
        ResponseAPDU r=transmit(Commands.getHello());
        if(r.getSW()==0x9000){
            System.out.println("Data: "+Hex.bytesToHexString(r.getData())+"["+new String(r.getData())+"]");
        } else {
            throw new JCException("Error selecting bitcoin wallet");
        }
    }

    public boolean authentication(String pin) throws JCException, NoSuchAlgorithmException {
        //0. Set PIN
        Crypto.setPin(pin);

        //1. Get challenge
        ResponseAPDU r = simulator.transmitCommand(Commands.getChallenge());
        rndicc=r.getData();
        Crypto.SetICCRandom(rndicc);

        //2. Mutual authenticate
        r=simulator.transmitCommand(Commands.mutualAuthenticate(Crypto.GetMutualAuthenticateData()));

        if(Crypto.VerifyMutualAuthenticationResponse(r.getData())){
            secureMessaging=true;
            System.out.println("Auth ok.");
            return true;
        } else {
            secureMessaging=false;
            System.out.println("Authentication error: "+Hex.bytesToHexString(Arrays.copyOfRange(r.getBytes(),r.getBytes().length-2,2)));
            return false;
        }
    }

    public void getRetries() throws JCException {
        ResponseAPDU r=simulator.transmitCommand(Commands.getRetries());
        if(r.getSW()==0x9000){
            System.out.println("Data: "+Hex.bytesToHexString(r.getData()));
        } else {
            throw new JCException("Error getting the remaining retries.");
        }
    }

    public void getHello() throws JCException{
        ResponseAPDU r=transmit(Commands.getHello());
        System.out.println("getHallo: "+new String(r.getData()));
    }

    private ResponseAPDU transmit(CommandAPDU com) throws JCException {
        ResponseAPDU r;

        if(secureMessaging){
            CommandAPDU comw=Crypto.wrapAPDU(com);
            ResponseAPDU rs=simulator.transmitCommand(comw);
            if(rs.getSW()==0x9000) {
                APDUResponse resp = Crypto.unwrapResponse(rs.getData());
                byte[] rdata=new byte[resp.getData().length+2]; // +2 because we will add the SW
                System.arraycopy(resp.getData(),0,rdata,0,resp.getData().length);
                System.arraycopy(resp.getReturnCodeBA(),0,rdata,rdata.length-2,2);
                r = new ResponseAPDU(rdata);
            } else {
                throw new JCException("Error transmitting encrypted APDU: "+Hex.bytesToHexString(Arrays.copyOfRange(rs.getBytes(),rs.getBytes().length-2,2)));
            }
        } else {
            r=simulator.transmitCommand(com);
        }

        if(r.getSW()==0x9000) {
            System.out.println("Decrypted data: " + Hex.bytesToHexString(r.getData()));
        } else {
            throw new JCException("Error transmitting encrypted APDU: "+Hex.bytesToHexString(Arrays.copyOfRange(r.getBytes(),r.getBytes().length-2,2)));
        }

        return r;
    }

    /*
    public void testAuthAPDU(){
        ResponseAPDU r;

        CommandAPDU comx=Commands.testAuthenticated("Salut".getBytes());
        APDUCommand com=new APDUCommand("",comx.getCLA(),comx.getINS(),comx.getP1(),comx.getP2());
        com.setData(Transformations.fromPrimitives(comx.getData()));
        APDUCommand comP=Crypto.wrapAPDU(com);
        System.out.println(com);
        System.out.println(comP);
        CommandAPDU comxP=new CommandAPDU(comP.getCLA().intValue(),comP.getINS().intValue(),comP.getP1().intValue(),comP.getP2().intValue(),Transformations.toPrimitives(comP.getData()));
        r=simulator.transmitCommand(comxP);
        System.out.println("Response:"+Integer.toHexString(r.getSW()));
        System.out.println(Hex.bytesToHexString(r.getData()));
        try {
            System.out.println("Data: "+Hex.bytesToHexString(Crypto.unwrapResponse(r.getData())));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    */
}
