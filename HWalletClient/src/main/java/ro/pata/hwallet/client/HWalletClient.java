/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ro.pata.hwallet.client;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.wallet.UnreadableWalletException;

/**
 *
 * @author adi
 */
public class HWalletClient {
    
    public static void main(String[] args) throws UnreadableWalletException, BlockStoreException, UnknownHostException, InterruptedException, ExecutionException, IOException, InsufficientMoneyException{
        Scanner sc = new Scanner(System.in);
        String com;
        WalletTools wt=new WalletTools();
        
        while(!(com=sc.nextLine()).equals("x")){
            
            switch(com){
                case "con":
                    wt.ConnectToPeerNetwork();
                    break;
                case "sw":
                    wt.ShowWallet();
                    break;
                case "st":
                    wt.ShowTransactions();
                    break;
                default:
                    System.out.println("Unknown command.");
            }

        }
    }  
}
