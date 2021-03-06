/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.bitcoinj.ectest;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.params.TestNet3Params;
import org.spongycastle.util.encoders.Hex;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author 10051644
 */
public class Smartcard {
    public void test(){
        try {
            byte[] r;
            Card card=init();
            CardChannel channel = card.getBasicChannel();
            
            exec(channel,"00A404000657BDE83637647F","select");
            
            //Import key 1
            //exec(channel,"8001000000","key create"); //P1=00 do not generate keys on card
            //exec(channel,"8005000020ce902ecfb27f45c779cbaaef12eba7a0846fd0afe62e2b92376263eca7a2dd7c","set priv key");
            //exec(channel,"800600004104df428c714234365ae047e7a640ffbd2a5283ec9482fc24716f7338034855546392334e520be70215cf46976d78967d6fa4d0d740996939fac85a8a62d88ebb01","set pub key");
            
            //Sign data
            //exec(channel,"800700000C436f746f6920566173696c65","signature");
            
            //Total keys
            exec(channel,"8008000000","registered keys"); 
            
            //GetKey
            //exec(channel,"8002000000","pub key");
            //exec(channel,"8003000000","priv key");
            
            
            //Keys status
//            r=exec(channel,"8008000000","registered keys"); 
//            byte totalKeys=r[0];
//            System.out.println("Registered keys: "+totalKeys);
//            for(int i=0;i<totalKeys;i++){ //The first byte in r[] contains the number of keys on card
//                r=exec(channel,"8002"+String.format("%2s",Integer.toHexString(i)).replace(" ", "0")+"0000","get pub key");
//                byte[] t=new byte[33];
//                t[0]=0x03;
//                for(int it=1;it<=32;it++){
//                    t[it]=r[it];
//                }
//                ECKey key=ECKey.fromPublicOnly(t);
//                System.out.println("Address: "+key.toAddress(TestNet3Params.get()));
//            }
            
            //exec(channel,"8008000000","free keys");
            
            //exec(channel,"8000EE0200","key status");
            //exec(channel,"8001000000","key create");
            //exec(channel,"8002000000","pub key");
            //exec(channel,"8003000000","priv key");
            //exec(channel,"8004000000","hash");
            //exec(channel,"8005000020ce902ecfb27f45c779cbaaef12eba7a0846fd0afe62e2b92376263eca7a2dd7c","set priv key");
            //exec(channel,"800600004104df428c714234365ae047e7a640ffbd2a5283ec9482fc24716f7338034855546392334e520be70215cf46976d78967d6fa4d0d740996939fac85a8a62d88ebb01","set pub key");
            
            card.disconnect(false);
        } catch (CardException ex) {
            Logger.getLogger(Smartcard.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private byte[] exec(CardChannel channel,String com,String id){
        try {
            System.out.println("apdu: "+com);
            ResponseAPDU r = channel.transmit(new CommandAPDU(Hex.decode(com)));
            System.out.println(id+" : " + javax.xml.bind.DatatypeConverter.printHexBinary(r.getBytes()));
            return r.getData();
        } catch (CardException ex) {
            Logger.getLogger(Smartcard.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    private Card init(){
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            System.out.println("Terminals: " + terminals);
            
            CardTerminal terminal = terminals.get(0);
            Card card = terminal.connect("T=1");
            System.out.println("card: " + card);            
            return card;            
        } catch (CardException ex) {
            Logger.getLogger(Smartcard.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
}
