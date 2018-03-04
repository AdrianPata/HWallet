package ro.pata.bitcoin.client;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import ro.pata.bitcoin.client.crypto.Crypto;
import ro.pata.bitcoin.client.crypto.JCException;

import java.security.NoSuchAlgorithmException;

public class Client {
    public static void main(String[] args){
        ApplicationContext ctx=new ClassPathXmlApplicationContext("Beans.xml");
        SmartCardInterface sc=(SmartCardInterface)ctx.getBean("scController");

        try {
            sc.selectApp();
            if(sc.authentication("0000")){
                sc.getHello();
            }else {
                sc.getRetries();
            }
        } catch (JCException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }



    }
}
