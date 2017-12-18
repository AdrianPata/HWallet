/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import static com.google.common.base.Preconditions.checkArgument;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Coin;
import static org.bitcoinj.core.Coin.COIN;
import static org.bitcoinj.core.Coin.MILLICOIN;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.TransactionOutput;
import static org.bitcoinj.core.Utils.HEX;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    
    public WalletTools(){
        BriefLogFormatter.init();
        try {
            wallet=Wallet.loadFromFile(new File("w.dat"));
            params = TestNet3Params.get();
            blockStore = new SPVBlockStore(params,new File("blockstore2.dat"));
            chain = new BlockChain(params, wallet, blockStore);
            peerGroup = new PeerGroup(params, chain);
        } catch (UnreadableWalletException | BlockStoreException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void ConnectToPeerNetwork(){
        try {
            peerGroup.start();
            peerGroup.addAddress(new PeerAddress(params, InetAddress.getByName("136.243.23.208")));
            peerGroup.waitForPeers(1).get();
            peerGroup.downloadBlockChain();
        } catch (UnknownHostException | InterruptedException | ExecutionException ex) {
            java.util.logging.Logger.getLogger(WalletTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void ShowWallet(){
        System.out.println(wallet);
    }
    
    public void KeyCreate(){
        ECKey key=new ECKey();
    }
    
    public void ShowTransactions(){
        Iterable<WalletTransaction> trans=wallet.getWalletTransactions();
        for(WalletTransaction t:trans){
            System.out.println("--------------------------------");
            //System.out.println(t.getTransaction());
            System.out.println("TXID: "+t.getTransaction().getHashAsString());
            if(t.getTransaction().getHashAsString().equals("03d36babf3182aae18fa9b1fdc67b11075fde5b1b88b98947e4b136dc8379676")){
                byte[] tx=t.getTransaction().bitcoinSerialize();
                System.out.println(HEX.encode(tx));
            }
            for(TransactionOutput o:t.getTransaction().getOutputs()){
                System.out.println("Out adr: "+o.getAddressFromP2PKHScript(params).toString());
            }
        }
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
    
    public static Coin valueOf(final int coins, final int mili) {
        checkArgument(mili < 1000);
        checkArgument(mili >= 0);
        checkArgument(coins >= 0);
        final Coin coin = COIN.multiply(coins).add(MILLICOIN.multiply(mili));
        return coin;
    }
}
