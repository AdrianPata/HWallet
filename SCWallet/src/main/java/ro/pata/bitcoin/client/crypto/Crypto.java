package ro.pata.bitcoin.client.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

public class Crypto {
    private static SecureRandom random;

    //Aceste chei au 192 biti, dar in realitate ultima este la fel cu prima deoarece Boncy Castle nu suporta 3DES cu doua chei
    private static byte[] KP_ENC={(byte)0x8f, (byte)0xc9, (byte)0xfe, (byte)0xae, (byte)0x1a, (byte)0xdd, (byte)0x23, (byte)0x39, (byte)0xc1, (byte)0x8a, (byte)0x99, (byte)0x4e, (byte)0x74, (byte)0xd1, (byte)0x18, (byte)0xc1, (byte)0x8f, (byte)0xc9, (byte)0xfe, (byte)0xae, (byte)0x1a, (byte)0xdd, (byte)0x23, (byte)0x39};
    private static byte[] KP_MAC={(byte)0xb7, (byte)0xa1, (byte)0x7f, (byte)0xa0, (byte)0x54, (byte)0x03, (byte)0x3c, (byte)0xe7, (byte)0x9f, (byte)0x92, (byte)0xc2, (byte)0xf4, (byte)0xcf, (byte)0xc7, (byte)0x98, (byte)0x9a, (byte)0xb7, (byte)0xa1, (byte)0x7f, (byte)0xa0, (byte)0x54, (byte)0x03, (byte)0x3c, (byte)0xe7};

    private static byte[] rndicc=new byte[8]; //Random from chip
    private static byte[] rndifd={(byte)0x8A, (byte)0x9E, (byte)0x4B, (byte)0x90, (byte)0x53, (byte)0xE6, (byte)0xC0, (byte)0x9B}; //Random from terminal (fixed for testing)
    private static byte[] kifd={(byte)0x47, (byte)0xb5, (byte)0x46, (byte)0xcc, (byte)0x1b, (byte)0xd0, (byte)0xc3, (byte)0x20, (byte)0x97, (byte)0xcd, (byte)0x0d, (byte)0x78, (byte)0x23, (byte)0x50, (byte)0xe0, (byte)0x4e}; //Key from terminal;
    private static byte[] kicc=new byte[16]; //Key from chip
    private static byte[] iv=new byte[8];
    private static SecretKeySpec kenc; //Session key
    private static SecretKeySpec kmac; //Session key
    private static byte[] ssc=new byte[8]; //Send Sequence Counter

    public static void init_test(){
        iv= Hex.hexStringToBytes("0000000000000000");
    }

    public static void SetICCRandom(byte[] b){
        rndicc=b;
    }

    public static byte[] GetMutualAuthenticateData(){
        //ENC(rndIFD[8] || rndICC[8] || kIFD[16] || padding) || MAC
        byte[] rez=null;

        try{
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            IvParameterSpec iv_param = new IvParameterSpec(iv);
            byte[] encryptedData;
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KP_ENC, "DESede"), iv_param);

            //Encrypt data
            String plain= DatatypeConverter.printHexBinary(rndifd);
            plain+=DatatypeConverter.printHexBinary(rndicc);
            plain+=DatatypeConverter.printHexBinary(kifd);
            //System.out.println("plain: "+plain);
            encryptedData = cipher.doFinal(Hex.hexStringToBytes(plain));
            //System.out.println("enc: "+DatatypeConverter.printHexBinary(encryptedData));

            //Calculate MAC
            Mac mac=Mac.getInstance("ISO9797Alg3Mac");
            mac.init(new SecretKeySpec(KP_MAC, "DESede"));
            byte[] calculatedMAC=mac.doFinal(pad7816_4(encryptedData,0,encryptedData.length));
            //System.out.println("mac: "+DatatypeConverter.printHexBinary(calculatedMAC));

            rez=new byte[encryptedData.length+calculatedMAC.length];
            System.arraycopy(encryptedData, 0, rez, 0, encryptedData.length);
            System.arraycopy(calculatedMAC, 0, rez, encryptedData.length, calculatedMAC.length);
            //System.out.println("auth data: "+DatatypeConverter.printHexBinary(rez));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            ex.printStackTrace();
        }

        return rez;
    }

    public static boolean VerifyMutualAuthenticationResponse(byte[] r){
        try {
            if(r.length!=40){
                System.out.println("Mutual auth response invalid. Length is "+r.length);
                return false;
            }

            byte[] mac=new byte[8];
            System.arraycopy(r, 32, mac, 0, 8);

            byte[] data=new byte[32];
            System.arraycopy(r, 0, data, 0, 32);

            //Calculate MAC
            Mac macInst=Mac.getInstance("ISO9797Alg3Mac");
            macInst.init(new SecretKeySpec(KP_MAC, "DESede"));
            byte[] calculatedMAC=macInst.doFinal(pad7816_4(data,0,data.length));

            //System.out.println("Received MAC: "+DatatypeConverter.printHexBinary(mac));
            //System.out.println("Calculated MAC: "+DatatypeConverter.printHexBinary(calculatedMAC));
            if(Arrays.equals(mac, calculatedMAC)){
                //System.out.println("MAC Ok.");
            } else {
                //System.out.println("MAC not Ok.");
                return false;
            }

            //Decrypt data
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            IvParameterSpec iv_param = new IvParameterSpec(iv);
            byte[] decryptedData;
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KP_ENC, "DESede"), iv_param);
            decryptedData=cipher.doFinal(data);
            //System.out.println("Data: "+DatatypeConverter.printHexBinary(decryptedData));

            //Verify iccRnd
            byte[] temp=new byte[8];
            System.arraycopy(decryptedData, 0, temp, 0, 8);
            if(Arrays.equals(rndicc, temp)){
                //System.out.println("ICC Rnd Ok.");
            } else {
                //System.out.println("ICC Rnd not Ok.");
                return false;
            }

            //Verify ifdRnd
            temp=new byte[8];
            System.arraycopy(decryptedData, 8, temp, 0, 8);
            if(Arrays.equals(rndifd, temp)){
                //System.out.println("IFD Rnd Ok.");
            } else {
                //System.out.println("IFD Rnd not Ok.");
                return false;
            }

            //Store ICC key
            System.arraycopy(decryptedData, 16, kicc, 0, 16);

            //Derivate session keys
            SessionKeyDerivation();
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            ex.printStackTrace();
        }
        return true;
    }

    public static void SessionKeyDerivation(){
        byte[] Kseed=new byte[16];
        int i = 0;
        for (byte b : kifd)
            Kseed[i] = (byte)(b ^ kicc[i++]);
        //System.out.println("Kseed: "+DatatypeConverter.printHexBinary(Kseed));

        //Generate session keys
        try {
            //Kenc
            byte[] hashin=new byte[20];
            byte[] c=Hex.hexStringToBytes("00000001");
            System.arraycopy(Kseed, 0, hashin, 0, Kseed.length);
            System.arraycopy(c, 0, hashin, Kseed.length, c.length);
            //System.out.println("hashin: "+DatatypeConverter.printHexBinary(hashin));

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(hashin);
            byte[] kencval=new byte[24]; //The version of Bouncy Castle that I use, requires 3DES with three keys
            System.arraycopy(messageDigest.digest(), 0, kencval, 0, 16);
            System.arraycopy(kencval, 0, kencval, 16, 8);
            //System.out.println("kseed: "+DatatypeConverter.printHexBinary(kseed));
            kenc=new SecretKeySpec(kencval, "DESede");

            //Kmac
            c=Hex.hexStringToBytes("00000002");
            System.arraycopy(c, 0, hashin, Kseed.length, c.length);
            //System.out.println("hashin: "+DatatypeConverter.printHexBinary(hashin));

            messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(hashin);
            byte[] kmacval=new byte[16];
            System.arraycopy(messageDigest.digest(), 0, kmacval, 0, 16);//;messageDigest.digest();
            //System.out.println("kmacval: "+DatatypeConverter.printHexBinary(kmacval));
            kmac=new SecretKeySpec(kmacval, "DESede");

            //SSC
            System.arraycopy(rndicc, 4, ssc, 0, 4);
            System.arraycopy(rndifd, 4, ssc, 4, 4);
            //System.out.println("ssc: "+DatatypeConverter.printHexBinary(ssc));
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        //System.out.println("Session keys ok.");
    }

    static void incrementSSC(){
        int l=ssc.length-1;
        int t;
        boolean reminder=false;

        do{
            t=Byte.toUnsignedInt(ssc[l]);
            if(t<0xFF) {
                ssc[l]++;
                reminder=false;
            } else {
                ssc[l]=0;
                if(l>0){
                    reminder=true;
                    l--;
                }
            }
        }while(reminder);

        //System.out.println("SSC: "+DatatypeConverter.printHexBinary(ssc));
    }

    //Functia preia un APDU normal si-l transforma intr-unul securizat (Secure Message)
    //CLA INS P1 P2              CLA INS P1 P2 Lc {DO 8Eh} 00h
    //CLA INS P1 P2 Le           CLA INS P1 P2 Lc {DO 97h || DO 8Eh} 00h
    //CLA INS P1 P2 Lc Data      CLA INS P1 P2 Lc {DO 87h || DO 8Eh} 00h
    //CLA INS P1 P2 Lc Data Le   CLA INS P1 P2 Lc {DO 87h || DO 97h || DO 8Eh} 00h
    public static CommandAPDU wrapAPDU(CommandAPDU com){
        //Creeaza un APDU nou pe baza celui original in care se va construi forma securizata
        APDUCommand scom=new APDUCommand("SecureCOM",com.getCLA(),com.getINS(),com.getP1(),com.getP2(),com.getNe());
        scom.setData(Transformations.fromPrimitives(com.getData()));

        //0b00001100 - Daca cei doi biti ai CLA sunt setati inseamna ca APDU-ul este securizat
        //Ma jos se seteaza cei doi biti
        byte cla= (byte) com.getCLA();
        cla|=0x0C; //0x0C = 0b00001100
        scom.setCLA(cla);

        scom.setLe((Byte)(byte)0);//Le pentru APDU securizat este intotdeauna 0x00.

        byte[] dataFinal;//array folosit la cateva procesari de mai jos

        // DO 87
        BERTLV do87=null;
        if(scom.getData()!=null){
            do87=new BERTLV("87"); //Datele se vor cripta intr-un DO cu cod 87
            byte[] dataPad=pad7816_4(Transformations.toPrimitives(scom.getData()), 0, scom.getData().length); //Datelor li se adauga pad 7816-4
            byte[] encryptedData=Crypto.Encrypt(dataPad); //Datele cu pad sunt criptate

            //Datelor criptate li se adauga un 0x01 in fata. Acesta este un flag care spune ca exista padding. 0x02: No padding
            dataFinal=new byte[encryptedData.length+1];
            dataFinal[0]=0x01;
            System.arraycopy(encryptedData, 0, dataFinal, 1, encryptedData.length);
            do87.setData(dataFinal);
        }

        // DO 97
        BERTLV do97=null;
        if(com.getNc()!=0){ //Se creeaza un obiect 97h doar daca exista Le in APDU-ul initial
            do97=new BERTLV("97");
            byte[] do97_le=new byte[1];
            do97_le[0]= (byte) com.getNc();
            do97.setData(do97_le);
        }

        // DO 8E
        BERTLV do8E=new BERTLV("8E"); //Acest DO contine MAC-ul
        byte[] headerPad=pad7816_4(scom.getHeader(), 0, 4); //Pentru calculare MAC este nevoie de header cu pad 7816-4
        incrementSSC();
        //Add necesary data for calculating MAC into one array
        int pos=0; //pozitia pentru append in array final
        dataFinal=new byte[ssc.length+headerPad.length+(do87!=null?do87.getBytes().length:0)+(do97!=null?do97.getBytes().length:0)];
        System.arraycopy(ssc, 0, dataFinal, pos, ssc.length); pos+=ssc.length;
        System.arraycopy(headerPad, 0, dataFinal, pos, headerPad.length);pos+=headerPad.length;
        if(do87!=null){System.arraycopy(do87.getBytes(), 0, dataFinal, pos, do87.getBytes().length);pos+=do87.getBytes().length;}
        if(do97!=null){System.arraycopy(do97.getBytes(), 0, dataFinal, pos, do97.getBytes().length);pos+=do97.getBytes().length;}
        //Pad data
        if(do87!=null || do97!=null) {dataFinal=pad7816_4(dataFinal,0,dataFinal.length);}
        //MAC
        byte[] mac=Crypto.Mac(dataFinal);
        //System.out.println("Data client:"+Hex.bytesToHexString(dataFinal));
        //System.out.println("MAC client :"+Hex.bytesToHexString(mac));
        do8E.setData(mac);

        //Create final APDU data
        dataFinal=new byte[(do87!=null?do87.getBytes().length:0)+(do97!=null?do97.getBytes().length:0)+do8E.getBytes().length];
        pos=0; //pozitia pentru append in array final
        if(do87!=null){System.arraycopy(do87.getBytes(), 0, dataFinal, pos, do87.getBytes().length); pos+=do87.getBytes().length;}
        if(do97!=null){System.arraycopy(do97.getBytes(), 0, dataFinal, pos, do97.getBytes().length); pos+=do97.getBytes().length;}
        System.arraycopy(do8E.getBytes(), 0, dataFinal, pos, do8E.getBytes().length);
        scom.setData(Transformations.fromPrimitives(dataFinal));

        //System.out.println("mac:"+DatatypeConverter.printHexBinary(mac));
        //System.out.println("sapdu:"+DatatypeConverter.printHexBinary(Transformations.toPrimitives(scom.getBytes())));

        return new CommandAPDU(scom.getCLA(),scom.getINS(),scom.getP1(),scom.getP2(),Transformations.toPrimitives(scom.getData()));
    }

    public static APDUResponse unwrapResponse(byte[] data) throws JCException{
        ArrayList<BERTLV> TLVList=BERTLV.getTLVList(data);
        incrementSSC(); //SSC se incrementeaza
        String macData=DatatypeConverter.printHexBinary(ssc); //Prim apozitie in sir este SSC-ul
        String mac="";
        String code="";
        String value="";

        for(BERTLV tlv:TLVList){
            if(!tlv.getTagName().equals("8E")){
                macData+=DatatypeConverter.printHexBinary(tlv.getBytes()); //Daca nu este tag MAC, il adauga la sirul pe care se va calcula MAC-ul
            } else {
                mac=tlv.getData(); //Daca este tag MAC, memoreaza-l
            }

            if(tlv.getTagName().equals("87")) value=tlv.getData(); //Valoarea intoarsa de APDU (criptata)
            if(tlv.getTagName().equals("99")) code=tlv.getData(); //Codul intors (9000h : Ok)
        }

        //Pad 7816-4 macData
        byte[] macDataByte=Transformations.toPrimitives(Transformations.hexStringToByteArray(macData));
        macDataByte=pad7816_4(macDataByte, 0, macDataByte.length);
        macData=DatatypeConverter.printHexBinary(macDataByte);

        //Verifica MAC
        if(!mac.equals(DatatypeConverter.printHexBinary(Mac(macData)))) throw new JCException("SM received bad MAC");

        //Elimina primul octet hex (2 caractere) din valoarea criptata (acesta specifica doar daca exista pad 7816-4 la datele criptate si nu face parte din acestea)
        if(value.length()>0) value=value.substring(2, value.length());
        //Decrypt
        if(value.length()>0) value=DatatypeConverter.printHexBinary(Decrypt(value));
        //Elimina pad 7816-4
        if(value.length()>0) value=unpad7816_4(value);

        return new APDUResponse(code,Transformations.toPrimitives(Transformations.hexStringToByteArray(value)));
    }

    public static byte[] Decrypt(String data){
        return Decrypt(Transformations.toPrimitives(Transformations.hexStringToByteArray(data)));
    }

    public static byte[] Decrypt(byte[] encryptedText){
        byte[] decryptedText=null;
        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            IvParameterSpec iv_param = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, kenc, iv_param);
            decryptedText=cipher.doFinal(encryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            ex.printStackTrace();
        }

        return decryptedText;
    }

    public static byte[] Encrypt(String data){
        return Encrypt(Transformations.toPrimitives(Transformations.hexStringToByteArray(data)));
    }

    public static byte[] Encrypt(byte[] decryptedText){
        byte[] encryptedText=null;
        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            IvParameterSpec iv_param = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, kenc, iv_param);
            encryptedText=cipher.doFinal(decryptedText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            ex.printStackTrace();
        }

        return encryptedText;
    }

    public static byte[] Mac(String data){
        return Mac(Transformations.toPrimitives(Transformations.hexStringToByteArray(data)));
    }

    public static byte[] Mac(byte[] mac){
        byte[] out=null;
        try {
            Mac macc=Mac.getInstance("ISO9797Alg3Mac");
            macc.init(kmac);
            out=macc.doFinal(mac);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            ex.printStackTrace();
        }

        return out;
    }

    public static byte[] pad7816_4(/*@ non_null */ byte[] in, int offset, int length) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(in, offset, length);
        out.write((byte)0x80);
        while (out.size() % 8 != 0) {
            out.write((byte)0x00);
        }
        return out.toByteArray();
    }

    public static String unpad7816_4(String data){
        int p=data.lastIndexOf("80");
        return data.substring(0,p);
    }

    /**
     * Generate ENC and MAC hashing the provided pin
     * @param pin is the password used to authenticate with the smart card
     */
    public static void setPin(String pin) throws NoSuchAlgorithmException {
        MessageDigest digest = null;
        digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(pin.getBytes(StandardCharsets.UTF_8));

        //Take the first 16 bytes and use them as a 112bit 3DES key (encoding)
        System.arraycopy(hash,0,KP_ENC,0,16);
        System.arraycopy(KP_ENC,0,KP_ENC,16,8); //The first key is used again since BouncyCastle supports only 192 bits keys

        //Use the last 16 bytes for mac key
        System.arraycopy(hash,16,KP_MAC,0,16);
        System.arraycopy(KP_MAC,0,KP_MAC,16,8); //The first key is used again since BouncyCastle supports only 192 bits keys
    }
}
