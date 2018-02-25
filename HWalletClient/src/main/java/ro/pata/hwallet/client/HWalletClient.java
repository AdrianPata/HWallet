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
        String ln,com;
        WalletTools wt=new WalletTools();
        
        while(!(ln=sc.nextLine()).equals("x")){
            com=ln.split(" ")[0];
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
                case "tt":
                    wt.testTransaction();
                    break;
                case "nk":
                    wt.newKey();
                    break;
                case "enk":
                    wt.ExternalKeyCreate();
                    break;
                case "sek":
                    wt.ShowExternalKey();
                    break;
                case "ns":
                    wt.newSigner();
                    break; 
                case "sso":
                    wt.showSpendableOutputs();
                    break;
                case "p":
                    wt.payToAddress(ln);
                    //wt.payToAddress("p 9bf19819a2c4f0c8a7f9319c22a2c140eede31a28a633d899206e5a78660f2e7 0 muPciPng1hpVuu5Z6gGZNztEfXBp7DJJFD 0.01");
                    break;
                case "sa":
                    wt.showHardwareAddresses();
                    break;
                case "chk":
                    wt.createHWKey();
                    break;
                default:
                    System.out.println("Unknown command.");
            }

        }
        
        wt.Save();
    }  
}
