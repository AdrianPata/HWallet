/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.signers.StatelessTransactionSigner;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;
import org.spongycastle.util.encoders.Hex;

/**
 *
 * @author 10051644
 */
public class HWTransactionSigner extends StatelessTransactionSigner{

    private static final EnumSet<Script.VerifyFlag> MINIMUM_VERIFY_FLAGS = EnumSet.of(Script.VerifyFlag.P2SH, Script.VerifyFlag.NULLDUMMY);
    
    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
        Transaction tx = propTx.partialTx;
        int numInputs = tx.getInputs().size();
        int i=0;
        for(TransactionInput txIn:tx.getInputs()){
            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey(), MINIMUM_VERIFY_FLAGS);
                System.out.println("Input "+i+" already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.");
                continue;
            } catch (ScriptException e) {
                // Expected.
            }
            
            RedeemData redeemData = txIn.getConnectedRedeemData(keyBag);
            Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();            
            Script inputScript = txIn.getScriptSig();
            
            ECKey key=null;
            try {
                key=ECKey.fromASN1(Files.readAllBytes(Paths.get("externalKey_01.dat")));
            } catch (IOException ex) {
                Logger.getLogger(HWTransactionSigner.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            byte[] script = redeemData.redeemScript.getProgram();
            
            if(txIn.getFromAddress().equals(key.toAddress(TestNet3Params.get()))){
                System.out.println("Found external key...");
                TransactionSignature signature = tx.calculateSignature(i, key, script, Transaction.SigHash.ALL, false);
                
                int sigIndex = 0;
                
                //This transaction was already signed by LocalTransactionSigner with the private key 0x03 (default for external key)
                //To sign it again first I have to remove the signature. 
                //The input script contains two chunks and the first one is the signature. I create a new script and add only the second chunk.
                ByteArrayOutputStream progStream = new ByteArrayOutputStream( );
                try {
                    progStream.write(0);
                    progStream.write(inputScript.getChunks().get(1).opcode);
                    progStream.write(inputScript.getChunks().get(1).data);
                } catch (IOException ex) {
                    Logger.getLogger(HWTransactionSigner.class.getName()).log(Level.SEVERE, null, ex);
                }
                
                inputScript=new Script(progStream.toByteArray());
                
                inputScript = scriptPubKey.getScriptSigWithSignature(inputScript, signature.encodeToBitcoin(), sigIndex);
                txIn.setScriptSig(inputScript);
            }
            
            
            
            
            i++;
        }
        return false;
    }
    
}
