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
import org.bitcoinj.core.Address;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Coin;
import static org.bitcoinj.core.Coin.CENT;
import static org.bitcoinj.core.Coin.COIN;
import static org.bitcoinj.core.Coin.MILLICOIN;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author adi
 */
public class HWalletClient {
    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    
    public static void main(String[] args) throws UnreadableWalletException, BlockStoreException, UnknownHostException, InterruptedException, ExecutionException, IOException, InsufficientMoneyException{
        BriefLogFormatter.init();
        
        log.info("adi");
        
        Wallet wallet;
        wallet=Wallet.loadFromFile(new File("w.dat"));

        NetworkParameters params = TestNet3Params.get();
        SPVBlockStore blockStore = new SPVBlockStore(params,new File("blockstore2.dat"));
        BlockChain chain = new BlockChain(params, wallet, blockStore);
        
        PeerGroup peerGroup = new PeerGroup(params, chain);
        peerGroup.start();
        peerGroup.addAddress(new PeerAddress(params, InetAddress.getByName("136.243.23.208")));
        peerGroup.waitForPeers(1).get();
        peerGroup.downloadBlockChain();
        
        Coin c=wallet.getBalance();
        System.out.println("Coin:"+c);
        
        List<ECKey> keys=wallet.getImportedKeys();
        System.out.println("Keys: "+keys.size());
        ECKey key=keys.get(0);
        System.out.println(key.toAddress(params));
        
        Address to = Address.fromBase58(params, "mhAPRv6uQ8YxrVBvV3sAKCiw1VHnAEpMnu");
        c=valueOf(0,10);
        SendRequest req = SendRequest.to(to, c);
        wallet.completeTx(req);
        Transaction t2 = req.tx;
        
        
        Iterable<WalletTransaction> trans=wallet.getWalletTransactions();
        for(WalletTransaction t:trans){
            System.out.println("--------------------------------");
            System.out.println(t.getTransaction());
        }
        
        System.out.println("Unspent: "+wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        System.out.println("All: "+wallet.getTransactions(true).size());
        System.out.println("Trans source: "+t2.getConfidence().getSource());
        System.out.println("Trans purpose: "+t2.getPurpose());
        System.out.println("Inputs: "+t2.getInputs().size());
        System.out.println("Outputs: "+t2.getOutputs().size());
        System.out.println("Dest: "+t2.getOutput(0).getScriptPubKey().getToAddress(params));
        System.out.println("Address: "+t2.getOutputs().get(1).getScriptPubKey().getToAddress(params));
        System.out.println("Value: "+t2.getOutputs().get(1).getValue());
        //t2.getInputs().get(0).verify();
        
        wallet.saveToFile(new File("w.dat"));
    }
    
    public static Coin valueOf(final int coins, final int mili) {
        checkArgument(mili < 1000);
        checkArgument(mili >= 0);
        checkArgument(coins >= 0);
        final Coin coin = COIN.multiply(coins).add(MILLICOIN.multiply(mili));
        return coin;
    }
}
