/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import static com.google.common.base.Preconditions.checkArgument;
import com.google.common.io.Files;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Coin;
import static org.bitcoinj.core.Coin.COIN;
import static org.bitcoinj.core.Coin.MILLICOIN;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

/**
 *
 * @author adi
 */
public class WalletTools {
    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);

    private Wallet wallet;
    private NetworkParameters params;
    private SPVBlockStore blockStore;
    private BlockChain chain;
    private PeerGroup peerGroup;
    private SmartCard smartCard;
    
    public WalletTools(){
        BriefLogFormatter.init();
        try {
            smartCard=SmartCard.getInstance();
            
            wallet=Wallet.loadFromFile(new File("w.dat"));
            wallet.autosaveToFile(new File("w.dat"), 1, TimeUnit.MINUTES, null);
            params = TestNet3Params.get();
            blockStore = new SPVBlockStore(params,new File("blockstore3.dat"));
            chain = new BlockChain(params, wallet, blockStore);
            peerGroup = new PeerGroup(params, chain);
        } catch (UnreadableWalletException | BlockStoreException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void Save(){
        try {
            wallet.saveToFile(new File("w.dat"));
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void ConnectToPeerNetwork(){
        try {
            peerGroup.start();
            //peerGroup.addAddress(new PeerAddress(params, InetAddress.getByName("136.243.23.208")));
            //peerGroup.addAddress(new PeerAddress(params, InetAddress.getByName("176.9.89.217")));
            peerGroup.addAddress(new PeerAddress(params, InetAddress.getByName("176.9.89.217")));
            peerGroup.waitForPeers(1).get();
            peerGroup.downloadBlockChain();
        } catch (UnknownHostException | InterruptedException | ExecutionException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void ShowWallet(){
        System.out.println(wallet);
        
        List<ECKey> keyList=wallet.getImportedKeys();
        for(ECKey k:keyList){
            System.out.println(k.toAddress(params).toBase58()+" : "+k.toStringWithPrivate(null, params));
        }
    }
    
    public void ShowExternalKey(){
        try {
            ECKey key=ECKey.fromASN1(Files.toByteArray(new File("externalKey_01.dat")));
            key=key.decompress();
            ECKey pub=ECKey.fromPublicOnly(key.getPubKey());            
            Address adr=pub.toAddress(params);
            System.out.println("Address: "+adr.toBase58());
            
            System.out.println(key.toStringWithPrivate(null, params));
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void ExternalKeyCreate(){
        try {
            ECKey key=new ECKey();
            byte[] k=key.toASN1();
            Files.write(k, new File("externalKey.dat"));   
            
            byte[] priv=new byte[1];priv[0]=3; //Generate a fake private key
            wallet.importKey(ECKey.fromPrivateAndPrecalculatedPublic(priv, key.getPubKey()));
            
            System.out.println("Adress: "+ECKey.fromPrivateAndPrecalculatedPublic(priv, key.getPubKey()).toAddress(params).toBase58());
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void ShowTransactions(){
        Iterable<WalletTransaction> trans=wallet.getWalletTransactions();
        Coin available;
        
        for(WalletTransaction t:trans){
            System.out.println("--------------------------------");
            //System.out.println(t.getTransaction());
            System.out.println("TXID: "+t.getTransaction().getHashAsString());

            //byte[] tx=t.getTransaction().bitcoinSerialize();
            //System.out.println(HEX.encode(tx));

            for(TransactionInput o:t.getTransaction().getInputs()){
                System.out.println("In: "+o.getValue()+" from:"+o.getFromAddress());
            }
            
            available=Coin.ZERO;
            for(TransactionOutput o:t.getTransaction().getOutputs()){
                String so=o.getValue().toFriendlyString();
                so+=" to:"+o.getAddressFromP2PKHScript(params).toString();
                
                if(o.isMine(wallet) && o.isAvailableForSpending()){
                    available=available.add(o.getValue());
                    System.out.println("Out: "+so);
                }
            }
            System.out.println("Available to spend: "+available.toFriendlyString());
        }
    }
    
    //Show only outputs in hardware wallet
    public void showSpendableOutputs(){
        List<String> availableHWAddresses=smartCard.getWalletAddresses();
        
        for(TransactionOutput o:getSpendableTransactions()){        
            if(availableHWAddresses.contains(o.getAddressFromP2PKHScript(params).toString()))
                System.out.println(o.getValue().toFriendlyString()+" Adr: "+o.getAddressFromP2PKHScript(params)+" TXID: "+o.getParentTransactionHash()+" "+o.getIndex());
        }      
    }
    
    //Display all addresses on smart card
    public void showHardwareAddresses(){
        List<String> availableHWAddresses=smartCard.getWalletAddresses();
        
        for(String adr:availableHWAddresses){
            System.out.println(adr);
        }
    }
    
    //Generate new key pair on card
    public void createHWKey(){
        smartCard.createKeyPair();
    }
    
    //A string made of 5 parameters
    //1: the command to this procedure "p"
    //2: transaction hash
    //3: output index
    //4: address to pay to
    //5: ammount
    public void payToAddress(String ln){
        String[] com=ln.split(" ");
        if(com.length!=5){
            System.out.println("Incorrect parametters.");
            return;
        }
        
        String transactionHash=com[1];
        Integer outputIndex=Integer.parseInt(com[2]);
        String addressDest=com[3];
        TransactionOutput outputToUse=null;
        Coin valueToPay=Coin.parseCoin(com[4]);
        
        for(TransactionOutput o:getSpendableTransactions()){
            if(o.getParentTransactionHash().toString().equals(transactionHash) && o.getIndex()==outputIndex){
                outputToUse=o;
            }
        }
        
        if(outputToUse==null){
            System.out.println("Transaction not found.");
            return;
        }
        
        if(valueToPay.compareTo(outputToUse.getValue())>0){
            System.out.println("Unable to pay "+valueToPay.toFriendlyString()+". Available "+outputToUse.getValue().toFriendlyString()+".");
            return;
        }
        
        Transaction tx=new Transaction(params);
        tx.addInput(outputToUse);
        tx.addOutput(valueToPay, Address.fromBase58(params, addressDest)); //Pay to this address
        
        SendRequest req=SendRequest.forTx(tx);
        req.changeAddress=outputToUse.getAddressFromP2PKHScript(params); //Change address set to the same address used for payment
        req.recipientsPayFees=true;
        try {
            wallet.completeTx(req);
        } catch (InsufficientMoneyException ex) {
            System.out.println(ex.getMessage());
            return;
        }
        
        try{
            System.out.print("Verify...");
            tx.getInputs().get(0).verify();
            System.out.println("passed");
        } catch(ScriptException ex){
            System.out.println("failed");
            return;
        }
        
        System.out.println("Txid: "+tx.getHashAsString());
        wallet.commitTx(tx);
        Threading.waitForUserCode();
        wallet.setTransactionBroadcaster(peerGroup);
        Save();
    }
    
    public void testTransaction(){
        Transaction tx=new Transaction(params);
        Transaction txsource=null;
        
        Map<Sha256Hash,Transaction> txunspent=wallet.getTransactionPool(WalletTransaction.Pool.UNSPENT);
        for(Sha256Hash txhash: txunspent.keySet()){
            if(txhash.equals(Sha256Hash.wrap("9bf19819a2c4f0c8a7f9319c22a2c140eede31a28a633d899206e5a78660f2e7"))){
                System.out.println("Available: "+txunspent.get(txhash).getValueSentToMe(wallet));
                txsource=txunspent.get(txhash);
                break;
            }
        }
        
        
        if(txsource!=null) {
            try {
                List<TransactionOutput> outs=txsource.getWalletOutputs(wallet);
                for(TransactionOutput out:outs){
                    if(out.isMine(wallet) && out.isAvailableForSpending()){
                        tx.addInput(out);                    
                        System.out.println("Input added: "+out);
                    }
                }
                
                tx.addOutput(valueOf(0,10), Address.fromBase58(params, "muPciPng1hpVuu5Z6gGZNztEfXBp7DJJFD")); //Cont incasari
                SendRequest req=SendRequest.forTx(tx);
                req.changeAddress=Address.fromBase58(params, "mpbmESLjpHCZQ71T9nL6FzdCGz2dTytuW4");
                req.recipientsPayFees=true;
                wallet.completeTx(req);
                
                try{
                    System.out.print("Verify...");
                    tx.getInputs().get(0).verify();
                    System.out.println("passed");
                } catch(ScriptException ex){
                    System.out.println("failed");
                }
                
                System.out.println("Transaction: "+Hex.toHexString(tx.unsafeBitcoinSerialize()));
                
            } catch (InsufficientMoneyException ex) {
                java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        }
        
        //SendRequest req = SendRequest.to(to, c);
        
        //byte[] txraw=tx.bitcoinSerialize();
        //System.out.println(HEX.encode(txraw));
        
        System.out.println(tx);
    }
    
    public void newKey(){
        ECKey key=new ECKey();
        System.out.println("New key address: "+key.toAddress(params));
        wallet.importKey(key);
        Save();
    }
    
    //Adds a signer to the wallet. This is saved to wallet file and is available in the future.
    public void newSigner(){
        //wallet.addTransactionSigner(new HWTransactionSigner());
        System.out.println("Signers: "+wallet.getTransactionSigners().size());
        //Save();
    }
    
    public void test() throws IOException, UnreadableWalletException, BlockStoreException, InterruptedException, ExecutionException{
        
        
        log.info("adi");
        
        Coin c=wallet.getBalance();
        System.out.println("Coin:"+c);
        
        List<ECKey> keys=wallet.getImportedKeys();
        System.out.println("Keys: "+keys.size());
        ECKey key=keys.get(0);
        System.out.println(key.toAddress(params));
        
        System.out.println(wallet);
        
//        Address to = Address.fromBase58(params, "mhAPRv6uQ8YxrVBvV3sAKCiw1VHnAEpMnu");
//        c=valueOf(0,10);
//        SendRequest req = SendRequest.to(to, c);
//        wallet.completeTx(req);
//        Transaction t2 = req.tx;
        
        
        Iterable<WalletTransaction> trans=wallet.getWalletTransactions();
        for(WalletTransaction t:trans){
            System.out.println("--------------------------------");
            System.out.println(t.getTransaction());
            for(TransactionOutput o:t.getTransaction().getOutputs()){
                System.out.println("Out adr: "+o.getAddressFromP2PKHScript(params).toString());
            }
        }
        
//        System.out.println("Unspent: "+wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
//        System.out.println("All: "+wallet.getTransactions(true).size());
//        System.out.println("Trans source: "+t2.getConfidence().getSource());
//        System.out.println("Trans purpose: "+t2.getPurpose());
//        System.out.println("Inputs: "+t2.getInputs().size());
//        System.out.println("Outputs: "+t2.getOutputs().size());
//        System.out.println("Dest: "+t2.getOutput(0).getScriptPubKey().getToAddress(params));
//        System.out.println("Address: "+t2.getOutputs().get(1).getScriptPubKey().getToAddress(params));
//        System.out.println("Value: "+t2.getOutputs().get(1).getValue());
//        t2.getInputs().get(0).verify();
//        System.out.println("Txid: "+t2.getHashAsString());
//        
//        System.out.println("Commit...");
//        //wallet.commitTx(t2);
//        
//        wallet.saveToFile(new File("w.dat"));
//        System.out.println("Wait...");
//        Threading.waitForUserCode();
        
        //wallet.setTransactionBroadcaster(peerGroup);

        wallet.saveToFile(new File("w.dat"));
        
//        do{
//            Thread.sleep(1000);
//        }while(true);
    }
    
    private List<TransactionOutput> getSpendableTransactions(){
        Iterable<WalletTransaction> trans=wallet.getWalletTransactions();
        List<TransactionOutput> spendableOutputs=new ArrayList<>();
        
        for(WalletTransaction t:trans){
            for(TransactionOutput o:t.getTransaction().getOutputs()){
                if(o.isMine(wallet) && o.isAvailableForSpending()){
                    spendableOutputs.add(o);
                }
            }
        }
        
        return spendableOutputs;
    }
    
    public static Coin valueOf(final int coins, final int mili) {
        checkArgument(mili < 1000);
        checkArgument(mili >= 0);
        checkArgument(coins >= 0);
        final Coin coin = COIN.multiply(coins).add(MILLICOIN.multiply(mili));
        return coin;
    }
}
