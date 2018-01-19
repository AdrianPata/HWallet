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
        sc.test();        
        //testSig();
    }
    
    public static void testSig() throws IOException{
        //ECKey key=ECKey.fromASN1(Files.readAllBytes(Paths.get("key.der")));
        //ECKey key=ECKey.fromPrivate(Hex.decode("EB9361012C48490B3E8FC0E4C9BE3D763ABBC42D3C23CDE729E02D29720AFF78"));
        ECKey key=ECKey.fromPublicOnly(Hex.decode("04df428c714234365ae047e7a640ffbd2a5283ec9482fc24716f7338034855546392334e520be70215cf46976d78967d6fa4d0d740996939fac85a8a62d88ebb01"));
        System.out.println(key.decompress().toStringWithPrivate(null, null));
        
        
        
        
        
        byte[] msg="Cotoi Vasile".getBytes();
        System.out.println("msg: "+HEX.encode(msg));
        Sha256Hash msgh=Sha256Hash.of(msg);
        System.out.println("msgh: "+msgh);
        
        ECKey.ECDSASignature sig;//=key.sign(msgh);       
        sig=ECKey.ECDSASignature.decodeFromDER(Hex.decode("3045022022C4801C7546FB2C536746B3A557027B1FE11B822EFD9CD9F0588E163825224B0221009616846C1A9372B6834A31EC9F8FEEAB2A3132D8375EC93C7E33A0EA93B48C55"));
        
      
        System.out.println("verif: "+key.verify(msgh, sig)); 

        
        
        //byte[] asn1=key.toASN1();
        //Files.write(Paths.get("key.der"), asn1);
    }
}
