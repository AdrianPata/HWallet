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
import org.spongycastle.util.encoders.Hex;

/**
 *
 * @author 10051644
 */
public class Smartcard {
    public void test(){
        try {
            Card card=init();
            CardChannel channel = card.getBasicChannel();
            
            exec(channel,"00A404000657BDE83637647F","select");
            //exec(channel,"8000000000","key status");
            exec(channel,"8001000000","key create");
            exec(channel,"8002000000","pub key");
            exec(channel,"8003000000","priv key");
            exec(channel,"8004000000","hash");
            
            card.disconnect(false);
        } catch (CardException ex) {
            Logger.getLogger(Smartcard.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void exec(CardChannel channel,String com,String id){
        try {
            ResponseAPDU r = channel.transmit(new CommandAPDU(Hex.decode(com)));
            System.out.println(id+" : " + javax.xml.bind.DatatypeConverter.printHexBinary(r.getBytes()));
        } catch (CardException ex) {
            Logger.getLogger(Smartcard.class.getName()).log(Level.SEVERE, null, ex);
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
