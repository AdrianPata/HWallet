package ro.pata.bitcoin.client.crypto;

import javax.smartcardio.CommandAPDU;

public class Commands {
    public static CommandAPDU getChallenge(){
        return new CommandAPDU(0x80, 0x84, 0x00, 0x00);
    }

    public static CommandAPDU mutualAuthenticate(byte[] data){
        return new CommandAPDU(0x80, 0x82, 0x00, 0x00,data);
    }

    public static CommandAPDU getHello(){
        return new CommandAPDU(0x80, 0x02, 0x00, 0x00);
    }

    public static CommandAPDU getRetries(){
        return new CommandAPDU(0x80, 0x03, 0x00, 0x00);
    }

    public static CommandAPDU testAuthenticated(byte[] data) {return new CommandAPDU(0x80,0x01,0x00,0x00,data); }
}
