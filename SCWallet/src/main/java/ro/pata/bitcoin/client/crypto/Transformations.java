package ro.pata.bitcoin.client.crypto;

import java.nio.ByteBuffer;

/**
 *
 * @author A4YZTZZ
 */
public class Transformations {
    public static byte[] toPrimitives(Byte[] oBytes)
    {
        byte[] bytes = new byte[oBytes.length];

        for(int i = 0; i < oBytes.length; i++) {
            bytes[i] = oBytes[i];
        }

        return bytes;
    }

    public static Byte[] fromPrimitives(byte[] oBytes)
    {
        Byte[] bytes = new Byte[oBytes.length];

        for(int i = 0; i < oBytes.length; i++) {
            bytes[i] = oBytes[i];
        }

        return bytes;
    }

    public static int getBit(byte b,int pos){
        return (b >> pos) & 1;
    }

    public static int[] getBits(byte b){
        int[] ret=new int[8];

        for(int i=0;i<8;i++) ret[i]=getBit(b,i);

        return ret;
    }

    public static int getIntFromBits(byte source,int startBit,int endBit){
        int ret=0;
        for(int i=startBit;i>=endBit;i--){
            ret=ret+getBit(source,i);
            if(i!=endBit){
                ret=ret<<1;
            }
        }
        return ret;
    }

    public static int getLSB(byte b,int c){
        int ret=0;
        for(int i=c;i>=0;i--){
            ret=ret+getBit(b,i);
            if(i>0) ret=ret<<1;
        }
        return ret;
    }

    public static byte[] removeBytesFromLeft(byte[] b,int n){
        byte[] r=new byte[b.length-n];
        for(int i=n;i<b.length;i++){
            r[i-n]=b[i];
        }
        return r;
    }

    public static String byteToHex(byte b){
        return String.format("%2s",Integer.toHexString(b&0xFF).toUpperCase()).replace(' ', '0');
    }

    public static Byte[] hexStringToByteArray(String s) {
        int len = s.length();
        Byte[] data = new Byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] integerToByteArray(int n){
        String nString=Integer.toHexString(n);
        if((nString.length()%2)!=0) nString="0"+nString;

        byte[] temp=Transformations.toPrimitives(Transformations.hexStringToByteArray(nString));

        byte[] rez=new byte[temp.length];
        int p=0;
        for(byte b:temp){
            rez[p]=b;
            p++;
        }

        return rez;
    }

    public static Integer byteArrayToInteger(byte[] ba){
        ByteBuffer wrapped = ByteBuffer.wrap(ba);
        return wrapped.getInt();
    }

    public static Integer byteArrayToInt(byte[] b)
    {
        int value = 0;
        for (int i = 0; i < b.length; i++) {
            value += (b[i] & 0x000000FF);
            if(i!=(b.length-1)) value=value<<8;
        }
        return value;
    }

    public static Integer bytesToInt(byte... b){
        return byteArrayToInt(b);
    }

    public static boolean testBits(byte b,int b7,int b6,int b5,int b4,int b3,int b2,int b1,int b0){
        boolean ret=true;
        if(b7>=0 && getBit(b, 7)!=b7) ret=false;
        if(b6>=0 && getBit(b, 6)!=b6) ret=false;
        if(b5>=0 && getBit(b, 5)!=b5) ret=false;
        if(b4>=0 && getBit(b, 4)!=b4) ret=false;
        if(b3>=0 && getBit(b, 3)!=b3) ret=false;
        if(b2>=0 && getBit(b, 2)!=b2) ret=false;
        if(b1>=0 && getBit(b, 1)!=b1) ret=false;
        if(b0>=0 && getBit(b, 0)!=b0) ret=false;
        return ret;
    }

    public static String hexStringToString(String data){
        byte ba[]=toPrimitives(hexStringToByteArray(data));
        return new String(ba);
    }

    public static byte[] remove7816Padding(byte[] data){
        Integer padPos=0;
        for(int i=data.length-1;i>0;i--){
            if(data[i]==(byte)0x80){
                padPos=i; break;
            }
        }

        byte[] rez=new byte[padPos];
        for(int i=0;i<rez.length;i++){
            rez[i]=data[i];
        }

        return rez;
    }
}
