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
import org.spongycastle.util.encoders.Hex;

/**
 *
 * @author 10051644
 */
public class MainTest {
    public static void main(String[] args) throws IOException{
        Smartcard sc=new Smartcard();
        //sc.test();        
        testSig();
    }
    
    public static void testSig() throws IOException{
        //ECKey key=ECKey.fromASN1(Files.readAllBytes(Paths.get("key.der")));
        //ECKey key=ECKey.fromPrivate(Hex.decode("EB9361012C48490B3E8FC0E4C9BE3D763ABBC42D3C23CDE729E02D29720AFF78"));
        ECKey key=ECKey.fromPublicOnly(Hex.decode("04013F3343BD902785500B4B548B1555C263EF75D75869625AA7C782645BD79DE07CFD8B3C4D10B0EAB8BB4A3259FECF0935004E51720013393F24637BFA062678"));
        System.out.println(key.decompress().toStringWithPrivate(null, null));
        
        
        
        
        
        byte[] msg="ADI".getBytes();
        System.out.println("msg: "+HEX.encode(msg));
        Sha256Hash msgh=Sha256Hash.of(msg);
        System.out.println("msgh: "+msgh);
        
        ECKey.ECDSASignature sig;//=key.sign(msgh);       
        sig=ECKey.ECDSASignature.decodeFromDER(Hex.decode("30450221008E5CA6F321F19A4B987FBFBDBAAA5C418F5F999850617350EFAEAD3D75560EBD02203722C5FCEBDFD2B993AF3FD0EFD95D1F285604D727096DEDE8F2010475557BAA"));
        
      
        System.out.println("verif: "+key.verify(msgh, sig)); 

        
        
        //byte[] asn1=key.toASN1();
        //Files.write(Paths.get("key.der"), asn1);
    }
}
