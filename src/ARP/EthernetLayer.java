package ARP;
import java.util.ArrayList;
import java.util.Arrays;
public class EthernetLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    int IpHeader_size = 24;
    private class _ETHERNET_ADDR {
        private byte[] addr = new byte[6];
        public _ETHERNET_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
            this.addr[4] = (byte) 0x00;
            this.addr[5] = (byte) 0x00;
        }
        void setBroadAddr() {
            this.addr[0] = (byte) 0xff;
            this.addr[1] = (byte) 0xff;
            this.addr[2] = (byte) 0xff;
            this.addr[3] = (byte) 0xff;
            this.addr[4] = (byte) 0xff;
            this.addr[5] = (byte) 0xff;
        }
    } // ??諛댁뎽??
    private class _ETHERNET_Frame {
        byte[] enet_data;
        _ETHERNET_ADDR enet_dstaddr;
        _ETHERNET_ADDR enet_srcaddr;
        byte[] enet_type;
        int Header_Size = 14 + 7;
        int Address_Size = 6;
        int IP_Size = 4;
        byte[] check;
        public _ETHERNET_Frame() {
            this.enet_dstaddr = new _ETHERNET_ADDR();
            this.enet_srcaddr = new _ETHERNET_ADDR();
//            this.check = "success".getBytes();
            this.enet_type = new byte[2];
            this.enet_data = null;
            this.check = new byte[7];
        }
       
    }
    _ETHERNET_Frame enet_frame = new _ETHERNET_Frame();
    public EthernetLayer(String pName) {
        // super(pName);
        // TODO Auto-generated constructor stub
        pLayerName = pName;
        ResetHeader();
    }
    public void ResetHeader() {
        for (int i = 0; i < 6; i++) {
            enet_frame.enet_dstaddr.addr[i] = (byte) 0x00;
            enet_frame.enet_srcaddr.addr[i] = (byte) 0x00;
        }
        enet_frame.enet_type[0] = 0x00;
        enet_frame.enet_type[1] = 0x00;
        System.arraycopy("success".getBytes(), 0, enet_frame.check, 0, 7);
    }
    private byte[] ObjToByte(byte[] input, int length) {
        byte[] buf = new byte[length + enet_frame.Header_Size];
        System.arraycopy(enet_frame.enet_dstaddr.addr, 0, buf, 0, enet_frame.Address_Size);
        System.arraycopy(enet_frame.enet_srcaddr.addr, 0, buf, enet_frame.Address_Size, enet_frame.Address_Size);
        buf[12] = enet_frame.enet_type[0];
        buf[13] = enet_frame.enet_type[1];
        System.arraycopy(enet_frame.check,0, buf, 14, 7);
        System.arraycopy(enet_frame.enet_data, 0, buf, enet_frame.Header_Size, length);
        return buf;
    }
    public void setDst2Broad() {
        _ETHERNET_ADDR broad = new _ETHERNET_ADDR();
        broad.setBroadAddr();
        enet_frame.enet_dstaddr = broad;
    }
    public boolean BroadSend(byte[] input, int length) {
        
        System.out.println(enet_frame.check.length);
        byte[] bytes;
        setDst2Broad();//
        enet_frame.enet_data = input;
        enet_frame.enet_type[0] = (byte) 0x20;
        enet_frame.enet_type[1] = (byte) 0x90;
        bytes = ObjToByte(input, length);
        ((NILayer) this.GetUnderLayer(0)).Send(bytes, bytes.length);
        return true;
    }
    public boolean Send(byte[] input, int length) {
    
        byte[] bytes = new byte[length + enet_frame.Header_Size]; 
        for (int i = 0; i < 6; i++) {
            bytes[i] = input[i + 18];
        } 
        for (int i = 0; i < 6; i++) {
            bytes[i + 6] = enet_frame.enet_srcaddr.addr[i];
        } 
        enet_frame.enet_type[0] = (byte) 0x20;
        enet_frame.enet_type[1] = (byte) 0x90; 
        bytes[12] = enet_frame.enet_type[0];
        bytes[13] = enet_frame.enet_type[1];
        System.arraycopy(enet_frame.check,0, bytes, 14, 7);
        for (int i = 0; i < length; i++) {
            bytes[i + enet_frame.Header_Size] = input[i];
        }
        ((NILayer) this.GetUnderLayer(0)).Send(bytes, bytes.length); 
        return true;
    }
    public boolean ChatFileSend(byte[] input, int length) {
        System.out.println("Ethernet_ChatFile_Send");
        byte[] bytes = new byte[input.length + enet_frame.Header_Size];
        for (int i = 0; i < 6; i++) {
            bytes[i] = enet_frame.enet_dstaddr.addr[i];
        }
        for (int i = 0; i < 6; i++) {
            bytes[i + 6] = enet_frame.enet_srcaddr.addr[i];
        }
        enet_frame.enet_type[0] = (byte) 0x20;
        enet_frame.enet_type[1] = (byte) 0x80;
        bytes[12] = enet_frame.enet_type[0];
        bytes[13] = enet_frame.enet_type[1];
        System.arraycopy(enet_frame.check,0, bytes, 14, 7);
        for (int i = 0; i < length; i++) {
            bytes[i + enet_frame.Header_Size] = input[i];
        }
        ((NILayer) this.GetUnderLayer(0)).Send(bytes, bytes.length);
        return true;
    }
    public byte[] RemoveCappHeader(byte[] input, int length) {
        int rellen = length - enet_frame.Header_Size;
        byte[] input2 = new byte[rellen];
        for (int i = 0; i < rellen; i++) {
            input2[i] = input[i + enet_frame.Header_Size];
        }
        return input2;
    }
    public byte[] setHeaderMac(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            enet_frame.enet_srcaddr.addr[i] = input[i];
        }
        return input;
    }
    
    byte[] intToByte4(int value) {
        byte[] temp = new byte[4];
        temp[0] |= (byte) ((value & 0xFF000000) >> 24);
        temp[1] |= (byte) ((value & 0xFF0000) >> 16);
        temp[2] |= (byte) ((value & 0xFF00) >> 8);
        temp[3] |= (byte) (value & 0xFF);
        return temp;
    }
    public static int byte4Int(byte one, byte two, byte three, byte four) {
        int s1 = one & 0xFF;
        int s2 = two & 0xFF;
        int s3 = three & 0xFF;
        int s4 = four & 0xFF;
        return ((s1 >> 24) + (s2 >> 16) + (s3 >> 8) + s4);
    }
    public boolean IsItBroad(byte[] input) {
        for (int i = 0; i < enet_frame.Address_Size; i++) {
            if (input[i] == (byte) 0xff)
                continue;
            else {
                return false;
            }
        }
        return true;
    }
    public boolean IsItMyPacket(byte[] input) {
        for (int i = 0; i < enet_frame.Address_Size; i++) {
            if (enet_frame.enet_srcaddr.addr[i] == input[i + enet_frame.Address_Size])
                continue;
            else {
                return false;
            }
        }
        return true;
    }
   
    private boolean isIt2team(byte[] input) {
     byte[] tmp = new byte[7];
     System.arraycopy(input, 14, tmp, 0, 7);
     if(Arrays.equals(tmp, enet_frame.check)) {
      return true;
     }
     return false;
    }
    public synchronized boolean Receive(byte[] input) {
        if( ! isIt2team(input) ) {
         return false;
        }
       
        boolean MyPacket, Mine, Broadcast;
        if (input[13] == (byte) 0x80) {
            MyPacket = IsItMyPacket(input);
            if (MyPacket == true) {
                return false;
            } else {
                Broadcast = IsItBroad(input);
                if (Broadcast == true) {
                    return false;
                }
                byte data[];
                data = RemoveCappHeader(input, input.length);
                this.GetUpperLayer(1).Receive(data);
                return true;
            }
        } 
        else {
            MyPacket = IsItMyPacket(input);
            if (MyPacket == true) {
                return false;
            } else {
                MyPacket = IsItMyPacket(input);
                if (MyPacket == true) {
                    return false;
                } else {
                    Broadcast = IsItBroad(input);
                    if (Broadcast == false) {
                        if (input[27] == 2) {
                            byte data[];
                            data = RemoveCappHeader(input, input.length);
                            this.GetUpperLayer(0).Receive(data); 
                            return true;
                        }
                        return false;
                    }
                    byte data[];
                    data = RemoveCappHeader(input, input.length);
                    this.GetUpperLayer(0).Receive(data); 
                    return true;
                }
            }
        }
    }
   
    public boolean IPCollision(){
        ((IPLayer) this.GetUpperLayer(1)).IPCollision();
        return true;
    }
    public byte[] GetSrcAdd() {
        byte[] k = new byte[6];
        for (int i = 0; i < this.enet_frame.enet_srcaddr.addr.length; i++) {
            k[i] = enet_frame.enet_srcaddr.addr[i];
        }
        return k;
    }
    public void setDstAddr(byte[] givenDstMacAddr) {
        System.arraycopy(givenDstMacAddr, 0, enet_frame.enet_dstaddr.addr, 0, enet_frame.Address_Size);
    }
    public static int byte2Int(byte one, byte two) {
        int s1 = one & 0xFF;
        int s2 = two & 0xFF;
        return ((s1 << 8) + (s2 << 0));
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