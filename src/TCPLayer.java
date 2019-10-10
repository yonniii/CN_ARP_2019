import java.util.ArrayList;

public class TCPLayer implements BaseLayer {

    public class _TCP_HEADER{
        byte[] tcpDSTPort; //4
        byte[] tcpSrcPort; //4
        byte[] tcpSeq;
        byte[] tcpAck;
        byte tcpOffset;
        byte tcpFlag;
        byte[] tcpWindow;
        byte[] tcpCksum;
        byte[] tcpUrgptr;
        byte[] padding;
        byte[] tcpData;

        int dstIndex = 0;
        int dstSize = 2;
        int srcSize = 2;

        public _TCP_HEADER(){
            this.tcpDSTPort = new byte[dstSize];
            this.tcpSrcPort = new byte[srcSize];
            this.tcpSeq = new byte[4];
            this.tcpAck = new byte[4];
            this.tcpOffset = 0x00;
            this.tcpFlag = 0x00;
            this.tcpWindow = new byte[2];
            this.tcpCksum = new byte[2];
            this.tcpUrgptr = new byte[2];
            this.padding = new byte[4];
            this.tcpData = null;
        }
    }

    _TCP_HEADER tcpHeader = new _TCP_HEADER();
    int IPHEADERSIZE = 8;
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    int dstPort = 8888;
    int srcPort = 8888;

    public TCPLayer(String pName){
        pLayerName = pName;
        ResetHeader();
    }
    public void ResetHeader(){ tcpHeader = new _TCP_HEADER(); }

    private byte[] ObjToByte(_TCP_HEADER header, int length){
        byte[] buf = new byte[length + IPHEADERSIZE] ;
        System.arraycopy(header.tcpDSTPort, 0, buf, header.dstIndex, header.dstSize);
        System.arraycopy(header.tcpSrcPort, 0, buf, header.dstIndex+header.dstSize, header.srcSize);
//        System.arraycopy(header.ipDATA, 0, buf, 0+header.srcSize +header.dstSize, length);
        return buf;
    }

    public void setPorts(){
        this.setDstPort(this.dstPort,tcpHeader);
        this.setSrcPort(this.srcPort,tcpHeader);
    }

    void setDstPort(int pNum,_TCP_HEADER header){
        header.tcpDSTPort = intToByte2(pNum);
    }

    void setSrcPort(int pNum,_TCP_HEADER header){
        header.tcpSrcPort = intToByte2(pNum);
    }

    public boolean Send(String dstIpAddr){
        return true;
    }

    public boolean Receive(byte[] input){
        return true;
    }

    byte[] intToByte4(int value) { //바이트로 변경.
        byte[] temp = new byte[4];

        temp[0] |= (byte) ((value & 0xFF000000) >> 24);
        temp[1] |= (byte) ((value & 0xFF0000) >> 16);
        temp[2] |= (byte) ((value & 0xFF00) >> 8);
        temp[3] |= (byte) (value & 0xFF);

        return temp;
    }

    byte[] intToByte2(int value) { //정수형을 byte 2배열로 바꿈.
        byte[] temp = new byte[2];
        temp[1] = (byte) (value >> 8);
        temp[0] = (byte) value;

        return temp;
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
