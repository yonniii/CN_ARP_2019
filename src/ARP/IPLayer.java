package ARP;
import java.util.ArrayList;

public class IPLayer implements BaseLayer {

    public class _IP_HEADER {
        byte ipVerLen; // 1
        byte ipToS; // 1
        byte[] ipLen; // 2
        byte[] ipID; // 2
        byte[] ipFragOff; // 2
        byte ipTTL; // 1
        byte ipProto; // 1
        byte[] ipCksum; // 2
        byte[] ipDSTAddr; // 4
        byte[] ipSRCAddr; // 4
        byte[] ipPadding;
        byte[] ipDATA;

        public _IP_HEADER() {
            this.ipVerLen = 0x00;
            this.ipToS = 0x00;
            this.ipLen = new byte[2];
            this.ipID = new byte[2];
            this.ipFragOff = new byte[2];
            this.ipTTL = 0x00;
            this.ipProto = (byte) 6;
            this.ipCksum = new byte[2];
            this.ipDSTAddr = new byte[4];
            this.ipSRCAddr = new byte[4];
            this.ipPadding = new byte[4];
            this.ipDATA = null;
        }

        int dstIndex = 12;
        int srcSize = 4;
        int dstSize = 4;
        int IPHEADERSIZE = 24;
        int fragOffIndex = 6;
        int idIndex = 4;
        int protoIndex = 10;
    }


    _IP_HEADER ipHeader = new _IP_HEADER();
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    int MTU = 1460 - ipHeader.IPHEADERSIZE;
    public float fileStatus = 0;
    byte PACKET_TYPE_NONFRAG = (byte) 0x01;
    byte PACKET_TYPE_FIRST = (byte) 0x02;
    byte PACKET_TYPE_MID = (byte) 0x03;
    byte PACKET_TYPE_LAST = (byte) 0x04;
    byte[] receive_data_buffer;
    int Received_data_count = 0;


    public IPLayer(String pName) {
        pLayerName = pName;
        ResetHeader();
    }

    public void ResetHeader() {
        ipHeader = new _IP_HEADER();
    }

    private byte[] ObjToByte(_IP_HEADER header, byte[] input, int length) {
        byte[] buf = new byte[length + header.IPHEADERSIZE];
        buf[0] = header.ipVerLen;
        buf[1] = header.ipToS;
        System.arraycopy(header.ipLen, 0, buf, 2, 2);
        System.arraycopy(header.ipID, 0, buf, 4, 2);
        System.arraycopy(header.ipFragOff, 0, buf, 6, 2);
        System.arraycopy(header.ipDSTAddr, 0, buf, header.dstIndex, header.dstSize);
        System.arraycopy(header.ipSRCAddr, 0, buf, header.dstIndex + header.dstSize, header.srcSize);
        if (length != 0)
            System.arraycopy(input, 0, buf, header.IPHEADERSIZE, length);
        return buf;
    }



    public void setSrcIPAddress(byte[] srcIPAddress) {
        ipHeader.ipSRCAddr = srcIPAddress;
    }

    public void setDstIPAddress(byte[] dstIPAddress) {
        ipHeader.ipDSTAddr = dstIPAddress;
    }

    public int getFileStatus() {
        return (int) fileStatus;
    }

    private void setFileStatus(int i) {
        this.fileStatus = i;
    }


    class SendFrag_Thread implements Runnable {
        int intDataTotlen;
        byte[] inputData;
        _IP_HEADER header = new _IP_HEADER();
        public SendFrag_Thread(byte input[], int length) {
            this.intDataTotlen = length;
            this.inputData = input;
        }
        // @Override
        // public void run() {
        // setFileStatus(10);
        // byte[] dataWithHeader;
        // int packetSize;
        // int packetCount = (intDataTotlen / MTU);
        // int intLastPacketSize;
        // if ((intLastPacketSize = intDataTotlen % MTU) == 0) {
        // intLastPacketSize = MTU;
        // }
        //
        // for (int i = 0; i <= packetCount; i++) {
        // if (i == 0) {
        // ipHeader.ipToS = PACKET_TYPE_FIRST;
        // packetSize = MTU;
        // if (packetCount == 0) {
        // ipHeader.ipToS = PACKET_TYPE_NONFRAG;
        // packetSize = intLastPacketSize;
        // }
        // } else if (i != packetCount - 1) {
        // ipHeader.ipToS = PACKET_TYPE_MID;
        // packetSize = MTU;
        // } else {
        // ipHeader.ipToS = PACKET_TYPE_LAST;
        // packetSize = intLastPacketSize;
        // }
        // ipHeader.ipFragOff = intToByte2(intDataTotlen);
        // ipHeader.ipID = intToByte2(i);
        // ipHeader.ipLen = intToByte2(packetSize);
        // byte[] fragData = new byte[packetSize];
        // System.arraycopy(inputData, i*MTU , fragData, 0, packetSize);
        // dataWithHeader = ObjToByte(ipHeader, fragData, packetSize);
        // if (!((ARPLayer) GetUndeLayer(0)).chatSend(dataWithHeader,
        // dataWithHeader.length)) {
        // System.out.println("IPLayer - chat File ���� ����!");
        //// return false;
        // }
        // setFileStatus((int)((float) (i + 1) / (float) packetCount) * 100);
        // System.out.println(getFileStatus() +"%");
        // }
        @Override
        public void run() {
            byte[] dataToSend;
            byte[] dataWithHeader;
            int packetSize;
            int packetCount;
            int intLastPacketSize;
            if ((intLastPacketSize = intDataTotlen % MTU) == 0) {
                packetCount = (intDataTotlen / MTU) - 1;
                intLastPacketSize = MTU;
            } else {
                packetCount = (intDataTotlen / MTU);
            }
            ipHeader.ipFragOff = intToByte2(intDataTotlen);
            if (intDataTotlen > MTU) {
                dataToSend = new byte[MTU];
                for (int i = 0; i <= packetCount; i++) {
                    try {
                        Thread.sleep((long) 1);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    if (i != packetCount) {
                        System.arraycopy(inputData, i * MTU, dataToSend, 0, MTU);
                        ipHeader.ipID = intToByte2(i);
                        if (i == 0) { // ù��° �������� ��
                            ipHeader.ipToS = PACKET_TYPE_FIRST;
                            dataWithHeader = ObjToByte(ipHeader, dataToSend, MTU);
                            System.out.println("FileApp - Send 1 first data" + i );
                        } else { // �߰� �������� ��
                            ipHeader.ipToS = PACKET_TYPE_MID;
                            dataWithHeader = ObjToByte(ipHeader, dataToSend, MTU);
                            System.out.println("FileApp - Send 2 midle data" + i );
                        }
                        ((ARPLayer) GetUnderLayer(0)).chatSend(dataWithHeader, MTU + ipHeader.IPHEADERSIZE);
                    } else {
                        System.arraycopy(inputData, MTU * i, dataToSend, 0, intLastPacketSize);
                        ipHeader.ipToS = PACKET_TYPE_LAST;
                        dataWithHeader = ObjToByte(ipHeader, dataToSend, intLastPacketSize);
                        System.out.println("FileApp - Send 3 last data" + i );
                        ((ARPLayer) GetUnderLayer(0)).chatSend(dataWithHeader,
                                intLastPacketSize + ipHeader.IPHEADERSIZE);
                    }
                }
            } else {
                ipHeader.ipToS = PACKET_TYPE_NONFRAG;
                ipHeader.ipID = intToByte2(0);
                dataWithHeader = ObjToByte(ipHeader, inputData, intDataTotlen);
                System.out.println("FileApp - Send 0 no Fragmentaion data");
                ((ARPLayer) GetUnderLayer(0)).chatSend(dataWithHeader, intDataTotlen + ipHeader.IPHEADERSIZE);
            }
            return;
        }
    }


    public boolean Send(byte[] input, int lenth) {
        ipHeader.ipVerLen = 4;
        if (lenth == 24) {
            // ipHeader.ipDATA = input;
            byte[] buf = ObjToByte(ipHeader, input, lenth);
            int bufSize = buf.length;
            if (((ARPLayer) this.GetUnderLayer(0)).Send(buf, bufSize))
                return true;
            else
                return false;
        } else {
            // setFileStatus(10);
            // ((TCPLayer)this.GetUpperLayer(0)).setProgressBar(getFileStatus());
            // byte[] dataWithHeader;
            // int packetSize;
            // int packetCount = lenth / MTU;
            // int intLastPacketSize;
            // if ((intLastPacketSize = lenth % MTU) == 0) {
            // intLastPacketSize = MTU;
            // }
            //
            // for (int i = 0; i <= packetCount; i++) {
            // if (i == 0) {
            // ipHeader.ipToS = PACKET_TYPE_FIRST;
            // packetSize = MTU;
            // if (packetCount == 0) {
            // ipHeader.ipToS = PACKET_TYPE_NONFRAG;
            // packetSize = intLastPacketSize;
            // }
            // } else if (i != packetCount - 1) {
            // ipHeader.ipToS = PACKET_TYPE_MID;
            // packetSize = MTU;
            // } else {
            // ipHeader.ipToS = PACKET_TYPE_LAST;
            // packetSize = intLastPacketSize;
            // }
            // ipHeader.ipFragOff = intToByte2(lenth);
            // ipHeader.ipID = intToByte2(i);
            // ipHeader.ipLen = intToByte2(packetSize);
            // byte[] fragData = new byte[packetSize];
            // System.arraycopy(input, i*MTU , fragData, 0, packetSize);
            // dataWithHeader = ObjToByte(ipHeader, fragData, packetSize);
            // if (!((ARPLayer) GetUndeLayer(0)).chatSend(dataWithHeader,
            // dataWithHeader.length)) {
            // System.out.println("IPLayer - chat File ���� ����!");
            //// return false;
            // }
            // setFileStatus((int)((float) (i + 1) / (float) packetCount) * 100);
            // System.out.println(getFileStatus() +"%");
            // ((TCPLayer)this.GetUpperLayer(0)).setProgressBar(getFileStatus());
            // }
            // try {
            // Thread.sleep(500);
            // } catch (InterruptedException e) {
            // e.printStackTrace();
            // }
            SendFrag_Thread thread = new SendFrag_Thread(input, lenth);
            Thread object = new Thread(thread);
            object.start();
        }
        return false;
    }


    private byte[] removeIPHeader(byte[] input, int length) {
        int dataSize = length;
        byte[] buf = new byte[dataSize];
        System.arraycopy(input, ipHeader.IPHEADERSIZE, buf, 0, dataSize);
        return buf;
    }

    public boolean Receive(byte[] input) {
//        if(input[ipHeader.protoIndex] != ipHeader.ipProto){ //상위계층이 TCP인지 확인
//            return false;
//        }

        if (input.length < 48) { //TCP헤더와 IP헤더가 모두 들어있는 데이터인지 확인
            return false;
        }
        int totalDataLength = byte2ToInt(input[ipHeader.fragOffIndex], input[ipHeader.fragOffIndex + 1]); //단편화되지 않은 총 데이터 길이
        byte packetType = input[1]; //단편화 타입
        int int_last_Frame_size; //단편화했을 때의 마지막 길이
        int int_seq_num;
        int_seq_num = byte2ToInt(input[ipHeader.idIndex], input[ipHeader.idIndex + 1]);
        if ((int_last_Frame_size = totalDataLength % MTU) == 0) {
            int_last_Frame_size = MTU;
        }
        if (totalDataLength > MTU) { //단편화된 데이터인 경우
            if (receive_data_buffer == null) {
                receive_data_buffer = new byte[totalDataLength];
            }
            if (packetType == PACKET_TYPE_LAST) {
                System.arraycopy(input, ipHeader.IPHEADERSIZE, receive_data_buffer, int_seq_num * MTU,
                        int_last_Frame_size);
                Received_data_count += int_last_Frame_size;
//            if (Received_data_count >= totalDataLength) {
                ((TCPLayer) this.GetUpperLayer(0)).Receive(receive_data_buffer);
                receive_data_buffer = null;
//            }
            } else {
                System.arraycopy(input, ipHeader.IPHEADERSIZE, receive_data_buffer, int_seq_num * MTU, MTU);
                Received_data_count += MTU;
            }
        } else { //단편화되지 않은 데이터인 경우우
             receive_data_buffer = new byte[totalDataLength];
            System.arraycopy(input, ipHeader.IPHEADERSIZE, receive_data_buffer, 0, totalDataLength);
            ((TCPLayer) this.GetUpperLayer(0)).Receive(receive_data_buffer);
            receive_data_buffer = null;
        }
        return true;
    }


    // public boolean Receive(byte[] input) {
    // int dstIndex = ipHeader.dstIndex;
    // for (int i = 0; i < ipHeader.srcSize; i++) {
    // if (input[i + dstIndex] != ipHeader.ipSRCAddr[i])
    // return false;
    // }
    // int totalDataLength = byte2ToInt(input[ipHeader.fragOffIndex],
    // input[ipHeader.fragOffIndex + 1]);
    // byte packetType = input[1];
    // if (packetType == PACKET_TYPE_NONFRAG) {
    // ((TCPLayer) this.GetUpperLayer(0)).Receive(removeIPHeader(input,
    // totalDataLength));
    // setFileStatus(100);
    //
    // } else {
    // if (receivedData == null) {
    // receivedData = new byte[totalDataLength];
    // }
    // int bufIndex = byte2ToInt(input[ipHeader.idIndex], input[ipHeader.idIndex +
    // 1]) * MTU;
    // int packetLen = byte2ToInt(input[2], input[3]);
    // if (packetType == PACKET_TYPE_FIRST) {
    // System.arraycopy(removeIPHeader(input, packetLen), 0, receivedData, bufIndex,
    // packetLen);
    // } else if (packetType == PACKET_TYPE_MID) {
    // System.arraycopy(removeIPHeader(input, packetLen), 0, receivedData, bufIndex,
    // packetLen)
    // } else if (packetType == PACKET_TYPE_LAST) {
    // System.arrycopy(removeIPHeader(input, packetLen), 0, receivedData, bufIndex,
    // packetLen);
    // }
    // receivedPacketCount++;
    // int totalPacketCount = (totalDataLength / MTU) + 1;
    // setFileStatus((receivedPacketCount / totalPacketCount) * 100);
    //
    // if (receivedPacketCount == totalPacketCount) {
    // this.GetUpperLayer(0).Receive(receivedData);
    // receivedData = null;
    // }
    //
    // }
    // return true;
    // }

    public boolean IPCollision() {
        ((TCPLayer) this.GetUpperLayer(0)).IPCollision();
        return true;
    }

    byte[] intToByte2(int value) {
        byte[] byteArray = new byte[2];
        byteArray[1] = (byte) (value >> 8);
        byteArray[0] = (byte) (value);
        return byteArray;
    }

    int byte2ToInt(byte one0, byte two1) {
        int number = (one0 & 0xFF) | ((two1 & 0xFF) << 8);
        return number;
    }

    byte[] intToByte4(int value) {
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