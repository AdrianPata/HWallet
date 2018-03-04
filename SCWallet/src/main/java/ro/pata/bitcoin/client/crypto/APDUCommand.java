package ro.pata.bitcoin.client.crypto;

import org.apache.commons.lang.ArrayUtils;

import java.util.ArrayList;
import java.util.List;

public class APDUCommand {
    private Byte CLA;
    private Byte INS;
    private Byte P1;
    private Byte P2;
    private Byte[] Data=null;
    private Byte Le=null;
    private final String name;

    public Byte getCLA() {
        return CLA;
    }

    public void setCLA(Byte CLA) {
        this.CLA = CLA;
    }

    public Byte getINS() {
        return INS;
    }

    public void setINS(Byte INS) {
        this.INS = INS;
    }

    public Byte getP1() {
        return P1;
    }

    public void setP1(Byte P1) {
        this.P1 = P1;
    }

    public Byte getP2() {
        return P2;
    }

    public void setP2(Byte P2) {
        this.P2 = P2;
    }

    public Byte getLe() {
        return Le;
    }

    public void setLe(Byte Le) {
        this.Le = Le;
    }


    public APDUCommand(String name,int CLA,int INS,int P1,int P2,int Le){
        this.CLA=(byte)CLA;
        this.INS=(byte)INS;
        this.P1=(byte)P1;
        this.P2=(byte)P2;
        this.Le=(byte)Le;
        this.name=name;
    }

    public APDUCommand(String name,int CLA,int INS,int P1,int P2){
        this.CLA=(byte)CLA;
        this.INS=(byte)INS;
        this.P1=(byte)P1;
        this.P2=(byte)P2;
        this.name=name;
    }

    public APDUCommand(APDUCommand c){
        this.CLA=c.CLA;
        this.INS=c.INS;
        this.P1=c.P1;
        this.P2=c.P2;
        this.name=c.name;
        if(c.Le!=null) this.Le=c.Le;
        if(c.Data!=null && c.Data.length>0){
            this.Data=new Byte[c.Data.length];
            for(int i=0;i<c.Data.length;i++){
                this.Data[i]=c.Data[i];
            }
        }
    }

    public Byte[] getBytes(){
        List<Byte> commandBytes=new ArrayList<>();
        if(CLA!=null) commandBytes.add(CLA);
        if(INS!=null) commandBytes.add(INS);
        if(P1!=null) commandBytes.add(P1);
        if(P2!=null) commandBytes.add(P2);
        if(Data!=null && Data.length>0) commandBytes.add((byte)Data.length); //Lc
        if(Data!=null && Data.length>0) {
            for(Byte b:Data){
                commandBytes.add(b);
            }
        }
        if(Le!=null) commandBytes.add(Le);

        Byte[] res=new Byte[commandBytes.size()];
        return commandBytes.toArray(res);
    }

    public void setData(Byte[] data){
        this.Data=data;
    }

    public Byte[] getData(){
        return this.Data;
    }

    public byte[] getHeader(){
        byte[] rez=new byte[4];
        rez[0]=CLA;
        rez[1]=INS;
        rez[2]=P1;
        rez[3]=P2;
        return rez;
    }

    @Override
    public String toString(){
        return "==>"+name+" "+ Hex.bytesToHexString(ArrayUtils.toPrimitive(getBytes()));
    }
}

