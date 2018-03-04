package ro.pata.bitcoin.client.crypto;

public class APDUResponse {
    private String returnCode;
    private byte[] data;

    public APDUResponse(String returnCode,byte[] data){
        this.returnCode=returnCode;
        this.data=data;
    }

    public String getReturnCodeStr() {
        return returnCode;
    }

    public byte[] getReturnCodeBA(){
        return Hex.hexStringToBytes(returnCode);
    }

    public byte[] getData() {
        return data;
    }

}
