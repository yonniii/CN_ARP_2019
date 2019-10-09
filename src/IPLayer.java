import java.util.ArrayList;

public class IPLayer implements BaseLayer {

    public class _IP_HEADER{
        byte[] ipSrcAddr; //4
        byte[] ipDSTAddr; //4
        byte[] ipDATA;

        int srcSize = 4;
        int dstSize = 4;

        public _IP_HEADER(){
            this.ipSrcAddr = new byte[4];
            this.ipDSTAddr = new byte[4];
            this.ipDATA = null;
        }
    } //헤더 총 8바이트

    _IP_HEADER ipHeader = new _IP_HEADER();
    final int IPHEADERSIZE = 8;
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    public IPLayer(String pName){
        pLayerName = pName;
        ResetHeader();
    }
    public void ResetHeader(){ ipHeader = new _IP_HEADER(); }

    private byte[] ObjToByte(_IP_HEADER header, int length){
        byte[] buf = new byte[length + IPHEADERSIZE] ;
        System.arraycopy(header.ipSrcAddr, 0, buf, 0, header.srcSize);
        System.arraycopy(header.ipDSTAddr, 0, buf, 0+header.srcSize, header.dstSize);
//        System.arraycopy(header.ipDATA, 0, buf, 0+header.srcSize +header.dstSize, length);
        return buf;
    }

    public void setSrcIPAddress(String srcIPAddress){
        ipHeader.ipSrcAddr[0] = ((byte) Integer.parseInt(srcIPAddress.substring(0, 3)));
        ipHeader.ipSrcAddr[1] = ((byte) Integer.parseInt(srcIPAddress.substring(3, 6)));
        ipHeader.ipSrcAddr[2] = ((byte) Integer.parseInt(srcIPAddress.substring(6, 9)));
        ipHeader.ipSrcAddr[3] = ((byte) Integer.parseInt(srcIPAddress.substring(9, 12)));
    }

    public void setDstIPAddress(String dstIPAddress) {
        ipHeader.ipDSTAddr[0] = ((byte) Integer.parseInt(dstIPAddress.substring(0, 3)));
        ipHeader.ipDSTAddr[1] = ((byte) Integer.parseInt(dstIPAddress.substring(3, 6)));
        ipHeader.ipDSTAddr[2] = ((byte) Integer.parseInt(dstIPAddress.substring(6, 9)));
        ipHeader.ipDSTAddr[3] = ((byte) Integer.parseInt(dstIPAddress.substring(9, 12)));
    }

    public boolean Send(String dstIpAddr){
        setDstIPAddress(dstIpAddr);
        ObjToByte(ipHeader,0);
//        if (((ARPLayer) this.getUnderLayer()).ARP_request_send(send_ip_data))
//            return true;
//        else
//            return false;
        return true;
    }

    public boolean Receive(byte[] input){
        int size = ipHeader.srcSize;
        for (int i = 0; i < size; i++) {
            if(input[i+size] != ipHeader.ipSrcAddr[0])
                return false;
        }
        return true;
    }


    @Override
    public String GetLayerName() {
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }

}
