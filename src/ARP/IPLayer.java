package ARP;

import java.util.ArrayList;

public class IPLayer implements BaseLayer {

    public class _IP_HEADER{
        byte  ipVerLen; //1
        byte ipToS; //1
        byte[] ipLen; //2
        byte[] ipID; //2
        byte[] ipFragOff; //2
        byte ipTTL; // 1
        byte ipProto; //1
        byte[] ipCksum; //2
        byte[] ipDSTAddr; //4
        byte[] ipSRCAddr; //4
        byte[] ipDATA;

        public _IP_HEADER() {
            this.ipVerLen = 0x00;
            this.ipToS = 0x00;
            this.ipLen = new byte[2];
            this.ipID = new byte[2];
            this.ipFragOff = new byte[2];
            this.ipTTL = 0x00;
            this.ipProto = 0x00;
            this.ipCksum = new byte[2];
            this.ipDSTAddr = new byte[4];
            this.ipSRCAddr = new byte[4];
            this.ipDATA = null;
        }
        int dstIndex = 12;
        int srcSize = 4;
        int dstSize = 4;
        int IPHEADERSIZE = 24;
    }

    _IP_HEADER ipHeader = new _IP_HEADER();
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    public IPLayer(String pName){
        pLayerName = pName;
        ResetHeader();
    }
    public void ResetHeader(){ ipHeader = new _IP_HEADER(); }

    private byte[] ObjToByte(_IP_HEADER header, int length){
        byte[] buf = new byte[length + header.IPHEADERSIZE] ;
        System.arraycopy(header.ipDSTAddr, 0, buf, header.dstIndex, header.dstSize);
        System.arraycopy(header.ipSRCAddr, 0, buf, header.dstIndex+header.dstSize, header.srcSize);
//        System.arraycopy(header.ipDATA, 0, buf, 0+header.srcSize +header.dstSize, length);
        return buf;
    }

    public void setSrcIPAddress(byte[] srcIPAddress){
        ipHeader.ipSRCAddr = srcIPAddress;
    }

    public void setDstIPAddress(String dstIPAddress) {
        String[] rawAddr = dstIPAddress.split("\\.");
        int[] str2int = new int[ipHeader.dstSize];
        for (int i = 0; i < rawAddr.length; i++) {
            str2int[i] = Integer.parseInt(rawAddr[i]);
        }
        byte[] int2byte = new byte[4];

        int2byte[0] |= (byte) (str2int[0]);
        int2byte[1] |= (byte) (str2int[1]);
        int2byte[2] |= (byte) (str2int[2]);
        int2byte[3] |= (byte) (str2int[3]);
        ipHeader.ipDSTAddr = int2byte;
    }

    public boolean Send(String dstIpAddr){
        setDstIPAddress(dstIpAddr);
        byte[] buf = ObjToByte(ipHeader,0);
        int bufSize=buf.length;
        if (((ARPLayer) this.GetUnderLayer(0)).Send(buf,bufSize))
            return true;
        else
            return false;
    }

    public boolean Receive(byte[] input){ //검증필요@@@ 받은 packet의 dst와 나의 주소인 src가 같은지 비교하도록 코드 작성
        int dstIndex = ipHeader.dstIndex;
        for (int i = 0; i < ipHeader.srcSize; i++) {
            if(input[i+dstIndex] != ipHeader.ipSRCAddr[i])
                return false;
        }
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