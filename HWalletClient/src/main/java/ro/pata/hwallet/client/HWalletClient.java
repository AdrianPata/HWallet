/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
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
public class HWalletClient {
    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    
    public static void main(String[] args) throws UnreadableWalletException, BlockStoreException, UnknownHostException, InterruptedException, ExecutionException, IOException{
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
        
        
        
        wallet.saveToFile(new File("w.dat"));
        
        List<ECKey> keys=wallet.getImportedKeys();
        ECKey key=keys.get(0);
        System.out.println(key.toAddress(params));
        
        Iterable<WalletTransaction> trans=wallet.getWalletTransactions();
        for(WalletTransaction t:trans){
            System.out.println("--------------------------------");
            System.out.println(t.getTransaction());
        }
    }
}
