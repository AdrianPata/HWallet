package ro.pata.bitcoin.client.crypto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author A4YZTZZ
 */
public class BERTLV {
    Map<String, String> tagNameList = new HashMap<>();

    private final int levelDeep;
    private final String parentName;

    private String tagName="";
    private boolean isConstructed=false;
    private String tagDescription="";
    private int tagBytes=1;

    private int len=0;
    private int lenBytes=1;
    private int totalLen=0;

    private byte[] value; //Daca este BER-TLV (contine alte TLV-uri) aceasta valoare este goala
    private String valueString="";

    List<BERTLV> DOList;

    public BERTLV(){
        levelDeep=0;
        parentName="";
        initTagNameList();
    }

    public BERTLV(int l,String parent){
        levelDeep=l;
        parentName=parent;
        initTagNameList();
    }

    public BERTLV(String tag){
        this();
        tagName=tag;
        tagBytes= Transformations.toPrimitives(Transformations.hexStringToByteArray(tagName)).length;
    }

    public String getTagName(){
        return tagName;
    }

    public String getData(){
        return valueString;
    }

    public void setData(byte[] data){
        len=data.length;
        value=new byte[len];
        valueString="";
        for(int i=0;i<len;i++){
            value[i]=data[i];
            valueString+=Transformations.byteToHex(data[i]);
        }

        if(len<=127){
            lenBytes=1;
        } else{
            lenBytes=Transformations.integerToByteArray(len).length+1;
        }
        totalLen=tagBytes+lenBytes+len;
    }

    public void parse(byte[] data){
        if(data==null) return;
        totalLen=data.length;

        //Parse Tag Field
        int[] tagBits=Transformations.getBits(data[0]);
        tagName+=Integer.toHexString(data[0]&0xFF).toUpperCase();

        if(tagBits[7]==0 && tagBits[6]==0) tagDescription="Universal class";
        if(tagBits[7]==0 && tagBits[6]==1) tagDescription="Application class";
        if(tagBits[7]==1 && tagBits[6]==0) tagDescription="Context-specific class";
        if(tagBits[7]==1 && tagBits[6]==1) tagDescription="Private class";

        if(tagBits[5]==1)isConstructed=true;//If bit5 is set: Constructed encoding (BER-TLV enc. V)

        int tagLen=Transformations.getLSB(data[0], 4);

        if(tagLen>30) { //Tag > 30 (long tag field, 2 or 3 bytes)
            tagBytes++;
            tagName+=Transformations.byteToHex(data[tagBytes-1]);
            while(Transformations.getBit(data[tagBytes-1],7)!=0){
                tagBytes++;
                tagName+=Transformations.byteToHex(data[tagBytes-1]);
            }
        }

        //Parse Length Field
        if(Transformations.getBit(data[tagBytes], 7)==0){ //If bit7 is 0, short length field
            //short length field
            len=Transformations.getLSB(data[tagBytes], 6);
        }else {
            //long length field (two or three bytes)
            lenBytes+=Transformations.getLSB(data[tagBytes], 6);
            len=len+Byte.toUnsignedInt(data[tagBytes+1]);
            if(lenBytes==3){
                len=len<<8;
                len=len+Byte.toUnsignedInt(data[tagBytes+2]);
            }
        }

        //Store value
        value=new byte[len];
        int start=tagBytes+lenBytes; //value starts after skipping 1 byte for tag + len bytes
        for(int i=0;i<len;i++){
            value[i]=data[start+i];
            valueString+=Transformations.byteToHex(data[start+i]);
        }

        //If it is Constructed, parse value
        if(isConstructed){
            DOList=new ArrayList<>();
            BERTLV tlv;
            while(value.length>0){
                tlv=new BERTLV(levelDeep+1,tagName);
                tlv.parse(value);
                DOList.add(tlv);
                value=Transformations.removeBytesFromLeft(value, tlv.getTotalLength());
            }
        }
    }

    public byte[] getBytes(){
        byte[] rez=new byte[getTotalLength()];
        byte[] tagByteArray=Transformations.toPrimitives(Transformations.hexStringToByteArray(tagName));
        byte[] lenByteArray;
        if(len<=127){//One byte length
            lenByteArray=new byte[1];
            lenByteArray[0]=(byte)len;
        } else {
            byte[] lenArray=Transformations.integerToByteArray(len);
            lenByteArray=new byte[lenBytes];
            lenByteArray[0]=(byte)(0x80+lenBytes-1);
            System.arraycopy(lenArray, 0, lenByteArray, 1, lenArray.length);
        }

        //Populate response TLV
        int p=0;
        System.arraycopy(tagByteArray, 0, rez, p, tagByteArray.length); p+=tagByteArray.length;
        System.arraycopy(lenByteArray, 0, rez, p, lenByteArray.length); p+=lenByteArray.length;
        byte[] data=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));
        System.arraycopy(data, 0, rez, p, data.length);

        return rez;
    }

    public int getTotalLength(){
        return len+tagBytes+lenBytes;
    }

    @Override
    public String toString(){
        String ret=getLevelHeader();
        ret+=tagName+", ";
        ret+=tagNameList.get(tagName)+", ";
        //ret+=tagDescription+", ";
        ret+="Constructed:"+Boolean.toString(isConstructed)+", ";
        //ret+="TagBytes:"+tagBytes+", ";
        //ret+="LenBytes:"+lenBytes+", ";
        ret+="ValLen:"+len+", ";
        //ret+="TotalLen:"+totalLen+", ";
        if(!isConstructed) ret+=valueString;
        ret+="\r\n";

        if(!isConstructed){
            List<String> det=getValueDetails();
            if(det.size()>0){
                for(String d:det){
                    ret+=getLevelHeader().replace("-", " ")+"  ";//Inlocuieste caracterul "-" care apare in mod normal in levelHeader cu spatiu
                    ret+=d;
                    ret+="\r\n";
                }
            }
        }


        if(isConstructed){
            for(BERTLV obj:DOList){
                ret+=obj.toString();
            }
        }

        return ret;
    }

    private String getLevelHeader(){
        StringBuilder sb = new StringBuilder( levelDeep );
        for( int i=0; i<levelDeep; i++ ) {
            sb.append( "--" );
        }
        return sb.toString();
    }

    //Primeste un array care contine mai multe TLV-uri concatenate
    //intoarce o lista cu obiecte BERTLV
    public static ArrayList<BERTLV> getTLVList(byte[] value){
        ArrayList<BERTLV> TLVList=new ArrayList<>();
        BERTLV tlv;
        while(value.length>0){
            tlv=new BERTLV();
            tlv.parse(value);
            TLVList.add(tlv);
            value=Transformations.removeBytesFromLeft(value, tlv.getTotalLength());
        }
        return TLVList;
    }

    private void initTagNameList(){
        tagNameList.put("E0","n/a");
        tagNameList.put("62","FCP File Control Parameters");
        tagNameList.put("64","FMD File Management Data");
        tagNameList.put("6F","FCI File Control Information");

        tagNameList.put("A0","Silicon information");
        tagNameList.put("A1","OS information");
        tagNameList.put("A2","Patch level information");
        tagNameList.put("A8","Runtime information");

        if(parentName.equals("A0")){ //Silicon information
            tagNameList.put("5F4D","IC manufacturer identifier according to ISO/IEC 7816-6");
            tagNameList.put("5F50","IC manufacturer URL (ASCII)");
        }

        if(parentName.equals("A1")){ //OS information
            tagNameList.put("5F4D","IC manufacturer identifier according to ISO/IEC 7816-6");
            tagNameList.put("5F50","Manufacturer URL (ASCII)");
            tagNameList.put("82","OS identifier (ASCII)");
            tagNameList.put("83","Version number (BCD)");
            tagNameList.put("84","Build date (BCD)");
        }

        if(parentName.equals("A2")){ //Patch level information
            tagNameList.put("82","Feature indicator (binary)");
            tagNameList.put("83","Version number (binary)");
            tagNameList.put("84","Build date (BCD)");
        }

        if(parentName.equals("62")){ //FCP File Control Parameters
            tagNameList.put("80","File size");
            tagNameList.put("81","File size");
            tagNameList.put("82","File descriptor (FD)");
            tagNameList.put("83","File identifier (FID)");
            tagNameList.put("84","DF name / Application ID");
            tagNameList.put("86","Security attributes in proprietary format");
            tagNameList.put("88","Short File Identifier (SFID)");
            tagNameList.put("8A","Life Cycle Status byte (LCSI)");
            tagNameList.put("A1","Security attribute template for physical interfaces");
            tagNameList.put("A5","Security attribute template for elementary/directory files");
            tagNameList.put("AB","Security attributes in expanded format");
        }

        if(parentName.equals("A5")){ //Proprietary Security Attributes for Elementary Files
            tagNameList.put("81","Authentication scheme (mandatory for all secret files)");
            tagNameList.put("82","Retry counter and its reset behavior and retry delay (mandatory for all secret files used for authentication)");
            tagNameList.put("83","Cryptographic algorithm and application class (mandatory for key files used for authentication and for password files)");
            tagNameList.put("85","Reset mask for verified secrets");
            tagNameList.put("86","Permission for Enable/Disable Verification Requirement (optional, only for password files)");
            tagNameList.put("87","Specific State of Enable/Disable Verification Requirement (optional, anyfile)");
            tagNameList.put("8D","RTC reset limit");
        }
    }

    //Interpreteaza valoarea tag-ului curent
    public List<String> getValueDetails(){
        List<String> retl=new ArrayList<>();
        String ret;

        if (isConstructed) return retl; //Daca continutul este format din alte TLV-uri nu avem ce interpreta

        //FCP - Tag rezultat in urma unui SELECT de fisier (File Control Parameters)
        if(parentName.equals("62")){
            //File Descriptor
            if(tagName.equals("82")){
                ret="";
                byte[] val=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));
                //File type
                if(val[0]==0x38) ret+="DF, ";
                if(val[0]==0x01) ret+="Transparent EF, ";
                if(val[0]==0x02) ret+="Record-oriented EF (linear, fixed size-records), ";
                if(val[0]==0x03) ret+="Record-oriented EF (linear, fixed size-records, STLV-encoded), ";
                if(val[0]==0x04) ret+="Record-oriented EF (linear, variable size-records), ";
                if(val[0]==0x05) ret+="Record-oriented EF (linear, variable size-records, STLV-encoded), ";
                if(val[0]==0x06) ret+="Record-oriented EF (cyclic), ";
                if(val[0]==0x07) ret+="Record-oriented EF (cyclic, STLV-encoded), ";

                if(val.length>=2){ //Data coding
                    ret+="Data coding: "+String.format("%02X ", val[1])+", ";
                }

                if(val.length>=3){ //Record size
                    ret+="Record size: "+Transformations.bytesToInt(val[2],val[3])+", ";
                }

                if(val.length>=5){ //Number of records
                    ret+="No of records: "+Transformations.bytesToInt(val[4],val[5])+", ";
                }
                retl.add(ret);
            }

            //Security Attributes in Proprietary Format
            if(tagName.equals("86")){
                byte[] val=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));
                int total=val.length/6;
                for(int i=0;i<total;i++){
                    int p=i*6;
                    ret="";
                    //Byte 1 - Instruction code
                    ret+="INS: "+String.format("%02X ", val[0+p]);
                    if(Transformations.getBit(val[0+i], 0)==0){
                        ret+="(All secrets must be proven) ";
                    } else {
                        ret+="(One of the secrets is enough) ";
                    }
                    //Byte 2 - Password ID
                    if(Transformations.getBit(val[1+p], 0)==1) ret+="Local password #1(SFID 11h) ";
                    if(Transformations.getBit(val[1+p], 1)==1) ret+="Local password #2(SFID 12h) ";
                    if(Transformations.getBit(val[1+p], 2)==1) ret+="Local password #3(SFID 13h) ";
                    if(Transformations.getBit(val[1+p], 3)==1) ret+="Local password #4(SFID 14h) ";
                    if(Transformations.getBit(val[1+p], 4)==1) ret+="Global password #1(SFID 11h) ";
                    if(Transformations.getBit(val[1+p], 5)==1) ret+="Global password #2(SFID 12h) ";
                    if(Transformations.getBit(val[1+p], 6)==1) ret+="Global password #3(SFID 13h) ";
                    if(Transformations.getBit(val[1+p], 7)==1) ret+="Global password #4(SFID 14h) ";
                    //Byte 3 - Key ID for global keys
                    if(Transformations.getBit(val[2+p], 0)==1) ret+="Global key #1(SFID 01h) ";
                    if(Transformations.getBit(val[2+p], 1)==1) ret+="Global key #2(SFID 02h) ";
                    if(Transformations.getBit(val[2+p], 2)==1) ret+="Global key #3(SFID 03h) ";
                    if(Transformations.getBit(val[2+p], 3)==1) ret+="Global key #4(SFID 04h) ";
                    if(Transformations.getBit(val[2+p], 4)==1) ret+="Global key #5(SFID 05h) ";
                    if(Transformations.getBit(val[2+p], 5)==1) ret+="Global key #6(SFID 06h) ";
                    if(Transformations.getBit(val[2+p], 6)==1) ret+="Global key #7(SFID 07h) ";
                    if(Transformations.getBit(val[2+p], 7)==1) ret+="Global key #8(SFID 08h) ";
                    //Byte 4 - Key ID for local keys
                    if(Transformations.getBit(val[3+p], 0)==1) ret+="Local key #1(SFID 01h) ";
                    if(Transformations.getBit(val[3+p], 1)==1) ret+="Local key #2(SFID 02h) ";
                    if(Transformations.getBit(val[3+p], 2)==1) ret+="Local key #3(SFID 03h) ";
                    if(Transformations.getBit(val[3+p], 3)==1) ret+="Local key #4(SFID 04h) ";
                    if(Transformations.getBit(val[3+p], 4)==1) ret+="Local key #5(SFID 05h) ";
                    if(Transformations.getBit(val[3+p], 5)==1) ret+="Local key #6(SFID 06h) ";
                    if(Transformations.getBit(val[3+p], 6)==1) ret+="Local key #7(SFID 07h) ";
                    if(Transformations.getBit(val[3+p], 7)==1) ret+="Local key #8(SFID 08h) ";
                    //Byte 5 - Secure Messaging options for cryptographic checksum
                    if(val[4+p]!=(byte)0xFF){
                        if(Transformations.getBit(val[4+p], 7)==0) ret+="Cryptographic checksum with global key, ";
                        if(Transformations.getBit(val[4+p], 7)==1) ret+="Cryptographic checksum with local key, ";
                        if(Transformations.getBit(val[4+p], 6)==0) ret+="Any initialization vector (IV), ";
                        if(Transformations.getBit(val[4+p], 6)==1) ret+="Random initialization vector (IV), ";
                        ret+="key SFID: "+Transformations.getIntFromBits(val[4+p], 4, 0)+", ";
                    }
                    //Byte 6 - Secure Messaging options for encryption
                    if(val[5+p]!=(byte)0xFF){
                        if(Transformations.getBit(val[5+p], 7)==0) ret+="Encryption with global key, ";
                        if(Transformations.getBit(val[5+p], 7)==1) ret+="Encryption with local key, ";
                        if(Transformations.getBit(val[5+p], 6)==0) ret+="Any initialization vector (IV), ";
                        if(Transformations.getBit(val[5+p], 6)==1) ret+="Random initialization vector (IV), ";
                        ret+="key SFID: "+Transformations.getIntFromBits(val[5+p], 4, 0)+", ";
                    }
                    retl.add(ret);
                }
            }

            //Life Cycle Status Integer (LCSI)
            if(tagName.equals("8A")){
                ret="";
                byte[] val=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));
                if(Transformations.testBits(val[0], 0, 0, 0, 0, 0, 0, 0, 1)) ret+="Creation state";
                if(Transformations.testBits(val[0], 0, 0, 0, 0, 0, 0, 1, 1)) ret+="Initialization state";
                if(Transformations.testBits(val[0], 0, 0, 0, 0, 0, 1, -1, 1)) ret+="Operational state (activated)";
                if(Transformations.testBits(val[0], 0, 0, 0, 0, 0, 1, -1, 0)) ret+="Operational state (deactivated)";
                if(Transformations.testBits(val[0], 0, 0, 0, 0, 1, 1, -1, -1)) ret+="Termination state";
                retl.add(ret);
            }
        }

        //Proprietary Security Attributes for Elementary Files
        if(parentName.equals("A5")){
            //Authentication scheme (mandatory for all secret files)
            if(tagName.equals("81")){
                ret="";
                byte[] val=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));
                if(val[0]==(byte)0x01) ret+="General / MaskTech scheme (deprecated)";
                if(val[0]==(byte)0x02) ret+="General / NETLINK compatible (deprecated)";
                if(val[0]==(byte)0x1F) ret+="General / Key used for secure messaging";
                if(val[0]==(byte)0x20) ret+="General / Key for symmetric encryption using Perform Security Operation";
                if(val[0]==(byte)0x10) ret+="Password based Authentication / PIN, stored as hashed value";
                if(val[0]==(byte)0x17) ret+="Password based Authentication / PIN, stored as plain value (deprecated)";
                if(val[0]==(byte)0x0D) ret+="Password based Authentication / Match-on-Card  Fingerprint";
                if(val[0]==(byte)0x0E) ret+="Password based Authentication / Match-on-Card  Face";
                if(val[0]==(byte)0x04) ret+="ICAO Passport protection according to TR-PKI / ICAO - Basic Access Control";
                if(val[0]==(byte)0x08) ret+="ICAO Passport protection according to TR-PKI / Active Authentication";
                if(val[0]==(byte)0x09) ret+="EAC according to TR-03110 v1.11 / Chip Authentication";
                if(val[0]==(byte)0x0A) ret+="EAC according to TR-03110 v1.11 / Terminal Authentication";
                if(val[0]==(byte)0x1D) ret+="EAP according to ISO/IEC 18013-3 / Chip Authentication";
                if(val[0]==(byte)0x1E) ret+="EAP according to ISO/IEC 18013-3 / Terminal Authentication";
                if(val[0]==(byte)0x0B) ret+="Health Card according to eCH-0064 / Card-to-Card Authentication";
                if(val[0]==(byte)0x11) ret+="PACE according to TR-PACE v1.01 and TR-03110 v2.05 / PACE/SAC  MRZ";
                if(val[0]==(byte)0x12) ret+="PACE according to TR-PACE v1.01 and TR-03110 v2.05 / PACE/SAC  CAN";
                if(val[0]==(byte)0x13) ret+="PACE according to TR-PACE v1.01 and TR-03110 v2.05 / PACE/SAC  PIN";
                if(val[0]==(byte)0x14) ret+="PACE according to TR-PACE v1.01 and TR-03110 v2.05 / PACE/SAC  PUK";
                if(val[0]==(byte)0x18) ret+="Digital Signature according to EN 14890 / Client/Server Authentication";
                if(val[0]==(byte)0x19) ret+="Digital Signature according to EN 14890 / Symmetric Device Authentication";
                retl.add(ret);
            }
            //Retry counter and its reset behavior and retry delay (mandatory for all secret files used for authentication)
            if(tagName.equals("82")){
                byte[] val=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));

                //byte 1
                retl.add("Retry counter(RTC): "+String.format("%02X ", val[0]));

                //byte 2
                ret="";
                if(Transformations.testBits(val[1], 0, 0, 0, 0, 0, 0, 0, 0)) {
                    ret+="RTC unused; unlimited number of authentication attempts allowed";
                }else {
                    if(Transformations.testBits(val[1], 0,-1, -1, -1, -1, -1, -1, -1)) ret+="RTC is reset upon both successful authentication and Reset Retry Counter";
                    if(Transformations.testBits(val[1], 1,-1, -1, -1, -1, -1, -1, -1)) ret+="RTC can only be reset using Reset Retry Counter";
                }
                ret+=", Reset value: "+Transformations.getIntFromBits(val[1], 6, 0);
                retl.add(ret);

                //byte 3+
                if(val.length>2){
                    ret="Waiting time: ";
                    for(int i=2;i<val.length;i++){
                        ret+=String.format("%02X ", val[i])+" ";
                    }
                    retl.add(ret);
                }
            }
            //Cryptographic algorithm and application class (mandatory for key files used for authentication and for password files)
            if(tagName.equals("83")){
                byte[] val=Transformations.toPrimitives(Transformations.hexStringToByteArray(valueString));

                //byte 1
                ret="";
                if(Transformations.testBits(val[0], 1, -1, -1, -1, -1, -1, -1, -1)) ret+="Secret File, ";
                if(Transformations.testBits(val[0], 1, 0, -1, -1, -1, -1, -1, -1)) ret+="Password file, ";
                if(Transformations.testBits(val[0], 1, 1, -1, -1, -1, -1, -1, -1)) ret+="Key File, ";
                if(Transformations.testBits(val[0], 1, 1, -1, -1, 1, -1, -1, -1)) ret+="Signature, ";
                if(Transformations.testBits(val[0], 1, 1, -1, -1, -1, 1, -1, -1)) ret+="Encryption, ";
                if(Transformations.testBits(val[0], 1, 1, -1, -1, -1, -1, 1, -1)) ret+="Cryptographic checksum (Secure Messaging), ";
                if(Transformations.testBits(val[0], 1, 1, -1, -1, -1, -1, -1, 1)) ret+="Authentication, ";

                //byte 2
                if(Transformations.testBits(val[1], 1, -1, -1, -1, -1, -1, -1, -1)) ret+="More bytes follow, ";
                if(Transformations.testBits(val[1], -1, 0, -1, -1, -1, -1, -1, -1)) ret+="Symmetric algorithm, ";
                if(Transformations.testBits(val[1], -1, 0, 0, 0, 1, 0, -1, -1)) ret+="DES key, ";
                if(Transformations.testBits(val[1], -1, 0, 0, 0, 1, 1, -1, -1)) ret+="3DES key (2 or 3 keys, depending on key length), ";
                if(Transformations.testBits(val[1], -1, 0, 0, 0, 0, 1, -1, -1)) ret+="AES key (128, 192 or 256 bit), ";
                if(Transformations.testBits(val[1], -1, -1, -1, -1, -1, 1, 0, 0)) ret+="ECB mode (encryption), CBC-MAC (Retail-MAC for 3DES), ";
                if(Transformations.testBits(val[1], -1, -1, -1, -1, -1, 1, 0, 1)) ret+="CBC mode (encryption), CBC-MAC (Retail-MAC for 3DES), ";
                if(Transformations.testBits(val[1], -1, -1, -1, -1, -1, 1, 1, 0)) ret+="CBC mode (encryption), CMAC, ";
                if(Transformations.testBits(val[1], -1, 1, -1, -1, -1, -1, -1, -1)) ret+="Asymmetric algorithm, ";
                if(Transformations.testBits(val[1], 0, -1, -1, -1, -1, -1, -1, -1)) ret+="Last byte, ";

                retl.add(ret);
            }
            //Reset mask for verified secrets
            if(tagName.equals("85")){

            }
            //Permission for Enable/Disable Verification Requirement (optional, only for password files)
            if(tagName.equals("86")){

            }
            //Specic State of Enable/Disable Verification Requirement (optional, any file)
            if(tagName.equals("89")){

            }
            //RTC reset limit
            if(tagName.equals("8D")){

            }
        }

        return retl;
    }
}
