package ARP;

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
        int dstPortSize = 2;
        int srcPortSize = 2;
        int headerSize;

        public _TCP_HEADER(){
            this.tcpDSTPort = new byte[dstPortSize];
            this.tcpSrcPort = new byte[srcPortSize];
            this.tcpSeq = new byte[4];
            this.tcpAck = new byte[4];
            this.tcpOffset = 0x00;
            this.tcpFlag = 0x00;
            this.tcpWindow = new byte[2];
            this.tcpCksum = new byte[2];
            this.tcpUrgptr = new byte[2];
            this.padding = new byte[4];
            this.tcpData = null;

            this.headerSize = 24;
        }
    }

    _TCP_HEADER tcpHeader = new _TCP_HEADER();
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    int dstPort = 8888;
    int srcPort = 8888;

    public TCPLayer(String pName){
        pLayerName = pName;
        ResetHeader();
    }
    public void ResetHeader(){ tcpHeader = new _TCP_HEADER(); }

    private byte[] ObjToByte(_TCP_HEADER header, int length){
        byte[] buf = new byte[length + header.headerSize] ;
        System.arraycopy(header.tcpDSTPort, 0, buf, header.dstIndex, header.dstPortSize);
        System.arraycopy(header.tcpSrcPort, 0, buf, header.dstIndex+header.dstPortSize, header.srcPortSize);
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


    public boolean Send(byte[] input){
//        this.tcpHeader.tcpData = input;
//        int dataLen = input.length;
//        byte[] buf = ObjToByte(tcpHeader,dataLen);
//        int bufSize = dataLen+tcpHeader.headerSize;
//        if (((IPLayer) this.GetUnderLayer(0)).Send(buf,bufSize)) ;
        this.tcpHeader.tcpData = input;
        int dataLen = 0;
        byte[] buf = ObjToByte(tcpHeader,dataLen);
        int bufSize = dataLen+tcpHeader.headerSize;
        if (((IPLayer) this.GetUnderLayer(0)).Send(buf,bufSize))
            return true;
        else
            return false;
    }

    public boolean Receive(byte[] input){
        if(!IsItMyPort(input))
            return false;
        byte[] buf = removeTCPHeader(input, input.length);
        if(((ApplicationLayer)this.GetUpperLayer(0)).Receive(buf))
            return true;
        else
            return false;
    }

    private boolean IsItMyPort(byte[] input){
        for (int i = 0; i < tcpHeader.srcPortSize; i++) {
            if (tcpHeader.tcpSrcPort[i] == input[i + tcpHeader.dstIndex]) //목적지이더넷주소가 자신의이더넷주소가아니면 false와 break
                continue;
            else {
                System.out.println("It isn't MyPort");
                return false;
            }
        }
        System.out.println("It is MyPort");
        return true;
    }

    private byte[] removeTCPHeader(byte[] input,int length){
        byte[] buf = new byte[length-tcpHeader.headerSize];
        System.arraycopy(input,tcpHeader.headerSize,buf,0,length-tcpHeader.headerSize);
        return buf;
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
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_aUnderLayer.add(nUnderLayerCount++, pUnderLayer);
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
        // nUpperLayerCount++;
    }

    @Override
    public String GetLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer(int nindex) {
        if (nindex < 0 || nindex > m_nUnderLayerCount || m_nUnderLayerCount < 0)
            return null;
        return p_aUnderLayer.get(nindex);
    }
    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);

    }

}
