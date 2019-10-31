package ARP;

import java.util.ArrayList;

public class TCPLayer implements BaseLayer {

    public class _TCP_HEADER {
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
        int offsetIndex = 16;

        public _TCP_HEADER() {
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

    byte chatType = (byte) 1;
    byte fileType = (byte) 2;

    public TCPLayer(String pName) {
        pLayerName = pName;
        ResetHeader();
        setSrcPort(8888);
        setDstPort(8888);
    }


    public void ResetHeader() {
        tcpHeader = new _TCP_HEADER();
    }

    private byte[] ObjToByte(_TCP_HEADER header, int length) {
        byte[] buf = new byte[length + header.headerSize];
        System.arraycopy(header.tcpDSTPort, 0, buf, header.dstIndex, header.dstPortSize);
        System.arraycopy(header.tcpSrcPort, 0, buf, header.dstIndex + header.dstPortSize, header.srcPortSize);
        buf[header.offsetIndex] = header.tcpOffset;
        if( length != 0 )
            System.arraycopy(header.tcpData, 0, buf, header.headerSize, length);
        return buf;
    }

    public void setDstPort(int pNum) {
        tcpHeader.tcpDSTPort = intToByte2(pNum);
    }

    public void setSrcPort(int pNum) {
        tcpHeader.tcpSrcPort = intToByte2(pNum);
    }

    int getInputSize(byte[] input) {
        if (input == null) {
            return 0;
        } else {
            return input.length;
        }
    }
    public boolean Send(byte[]input, byte type){
        tcpHeader.tcpOffset = type;
        tcpHeader.tcpData = input;
        int dataLen = getInputSize(input);
        byte[] buf = ObjToByte(tcpHeader, dataLen);
        int bufSize = dataLen + tcpHeader.headerSize;
        if (((IPLayer) this.GetUnderLayer(0)).Send(buf, bufSize))
            return true;
        else
            return false;
    }

    public boolean Send(byte[] input) {
        tcpHeader.tcpData = input;

        int dataLen = getInputSize(input);
        byte[] buf = ObjToByte(tcpHeader, dataLen);
        int bufSize = dataLen + tcpHeader.headerSize;
        if (((IPLayer) this.GetUnderLayer(0)).Send(buf, bufSize))
            return true;
        else
            return false;
    }

    public boolean Receive(byte[] input) {
        if (!IsItMyPort(input))
            return false;
        byte type = input[16];
        if(type == chatType){
            byte[] buf = removeTCPHeader(input, input.length);
            if (((ChatAppLayer) this.GetUpperLayer(0)).Receive(buf))
                return true;
            else
                return false;
        }else if( type == fileType){
            byte[] buf = removeTCPHeader(input, input.length);
            if (((FileAppLayer) this.GetUpperLayer(1)).Receive(buf))
                return true;
            else
                return false;
        }
        return false;
    }

    public boolean IPCollision(){
        ((ChatAppLayer) this.GetUpperLayer(0)).IPCollision();
        return true;
    }

    private boolean IsItMyPort(byte[] input) {
        for (int i = 0; i < tcpHeader.srcPortSize; i++) {
            if (tcpHeader.tcpSrcPort[i] == input[i + tcpHeader.dstIndex])
                continue;
            else {
                System.out.println("It isn't MyPort");
                return false;
            }
        }
        System.out.println("It is MyPort");
        return true;
    }

    private byte[] removeTCPHeader(byte[] input, int length) {
        byte[] buf = new byte[length - tcpHeader.headerSize];
        System.arraycopy(input, tcpHeader.headerSize, buf, 0, length - tcpHeader.headerSize);
        return buf;
    }

    byte[] intToByte4(int value) {
        byte[] temp = new byte[4];

        temp[0] |= (byte) ((value & 0xFF000000) >> 24);
        temp[1] |= (byte) ((value & 0xFF0000) >> 16);
        temp[2] |= (byte) ((value & 0xFF00) >> 8);
        temp[3] |= (byte) (value & 0xFF);

        return temp;
    }

    byte[] intToByte2(int value) {
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