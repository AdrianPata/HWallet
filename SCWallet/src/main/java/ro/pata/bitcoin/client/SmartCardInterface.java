package ro.pata.bitcoin.client;

import ro.pata.bitcoin.client.crypto.JCException;

import java.security.NoSuchAlgorithmException;

interface SmartCardInterface {
    void selectApp() throws JCException;
    boolean authentication(String pin) throws JCException, NoSuchAlgorithmException;
    void getRetries() throws JCException;
    void getHello() throws JCException;
}
