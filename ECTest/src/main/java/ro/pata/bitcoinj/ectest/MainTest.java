/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.bitcoinj.ectest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.bitcoinj.core.*;
import static org.bitcoinj.core.Utils.HEX;

/**
 *
 * @author 10051644
 */
public class MainTest {
    public static void main(String[] args) throws IOException{
        ECKey key=ECKey.fromASN1(Files.readAllBytes(Paths.get("key.der")));
        System.out.println(key.toStringWithPrivate(null, null));
        
        byte[] msg="ADI".getBytes();
        System.out.println("msg: "+HEX.encode(msg));
        Sha256Hash msgh=Sha256Hash.of(msg);
        System.out.println("msgh: "+msgh);
        
        ECKey.ECDSASignature sig=key.sign(msgh);
        
        System.out.println("verif: "+key.verify(msgh, sig)); 

        
        
        //byte[] asn1=key.toASN1();
        //Files.write(Paths.get("key.der"), asn1);
    }
}
