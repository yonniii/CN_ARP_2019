package ARP;

import java.util.ArrayList;

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
    } //생성자

    private class _ETHERNET_Frame {
        byte[] enet_data;
        _ETHERNET_ADDR enet_dstaddr;
        _ETHERNET_ADDR enet_srcaddr;
        byte[] enet_type;
        int Header_Size = 14;
        int Address_Size = 6;
        int IP_Size = 4;

        public _ETHERNET_Frame() {
            this.enet_dstaddr = new _ETHERNET_ADDR();
            this.enet_srcaddr = new _ETHERNET_ADDR();
            this.enet_type = new byte[2];
             this.enet_data = null;
        }
    }// 헤더 프레임 클래스와 생성자

    _ETHERNET_Frame enet_frame = new _ETHERNET_Frame();

    public EthernetLayer(String pName) {
        // super(pName);
        // TODO Auto-generated constructor stub
        pLayerName = pName;
        ResetHeader(); //생성자에서 헤더를 리셋한다.
    }

    public void ResetHeader() {
        for (int i = 0; i < 6; i++) {
            enet_frame.enet_dstaddr.addr[i] = (byte) 0x00;
            enet_frame.enet_srcaddr.addr[i] = (byte) 0x00;
        }
        enet_frame.enet_type[0] = 0x00;
        enet_frame.enet_type[1] = 0x00;
    } //헤더를 리셋한다.

   /*   public boolean Send(byte[] input, int length) { // 채팅용 send라서 비워둠

      System.out.println("Ethernet_Send");

      byte[] bytes = new byte[input.length + 14]; // 헤더 길이를 늘린 새로운 배열


      for (int i = 0; i < 6; i++) {
         bytes[i] = enet_frame.enet_dstaddr.addr[i];
      }
      for (int i = 0; i < 6; i++) {
         bytes[i + 6] = enet_frame.enet_srcaddr.addr[i];
      }

      enet_frame.enet_type[0] = (byte) 0x20;
      enet_frame.enet_type[1] = (byte) 0x80;
      bytes[12] = enet_frame.enet_type[0];
      bytes[13] = enet_frame.enet_type[1]; // 걍 한번 더 채워줌.
      for (int i = 0; i < length; i++) {
         bytes[i + 14] = input[i];
      } //헤더 이후의 값을 옮겨줌
      System.out.println(bytes.length + "Ethernet_헤더 붙은 놈 길이");
      System.out.println();
      this.GetUnderLayer().Send(bytes, bytes.length); // 하위레이어, 즉 NILayer로 내려보낸다.

       return true;
    }*/
    public void setDst2Broad() {
        _ETHERNET_ADDR broad = new _ETHERNET_ADDR();
        broad.setBroadAddr();
        enet_frame.enet_dstaddr = broad;
    }
    private byte[] ObjToByte(byte[] input, int length){
        byte[] buf = new byte[length + enet_frame.Header_Size] ;
        System.arraycopy(enet_frame.enet_dstaddr.addr, 0, buf,0, enet_frame.Address_Size);
        System.arraycopy(enet_frame.enet_srcaddr.addr, 0, buf, enet_frame.Address_Size, enet_frame.Address_Size);
        buf[12] = enet_frame.enet_type[0];
        buf[13] = enet_frame.enet_type[1];
        System.arraycopy(enet_frame.enet_data, 0 ,buf, enet_frame.Header_Size, length);
        return buf;
    }
    public boolean Send(byte[] input, int length) {
        System.out.println("Ethernet_Send");

        byte[] bytes; // 헤더 길이를 늘린 새로운 배열

        setDst2Broad();
        enet_frame.enet_data = input;
        enet_frame.enet_type[0] = (byte) 0x20;
        enet_frame.enet_type[1] = (byte) 0x90;

        bytes = ObjToByte(input,length);
        ((NILayer)this.GetUnderLayer(0)).Send(bytes, bytes.length);

        return true;
    }

    public byte[] RemoveCappHeader(byte[] input, int length) {
        int rellen = length + IpHeader_size;
        byte[] input2 = new byte[rellen];
        System.out.println(rellen);
        for (int i = 0; i < rellen; i++) {
            input2[i] = input[i + enet_frame.Header_Size];
        }
        return input2;

    }
    public byte[] setHeaderMac(byte[] input) {
        for(int i =0; i<input.length; i++) {
            enet_frame.enet_srcaddr.addr[i] = input[i];
        } //이더넷 헤더의 src 주소를 application에서 보낸 값들로 채워주는 함수
        return input;
    }
    //public boolean
   /*   public byte[] RemoveCappHeaderF(byte[] input, int length) {
      System.out.println("이더넷_파일 헤더떼는거_     " + length);
      int rellen = length + 12;
      byte[] input2 = new byte[rellen];
      System.out.println("늘어난 버퍼"+rellen);
      for (int i = 0; i < rellen ; i++) {
         input2[i] = input[i + 14];
      }
      return input2;

   }*/
    byte[] intToByte4(int value) { //바이트로 변경.
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

        return ((s1 >> 24 )+(s2 >> 16)+(s3 >> 8) + s4);
    }
    private boolean IsItMine(byte[] input) {
        for (int i = 0; i < enet_frame.Address_Size; i++) {
            if (enet_frame.enet_srcaddr.addr[i] == input[i]) //목적지이더넷주소가 자신의이더넷주소가아니면 false와 break
                continue;
            else {
                System.out.println("It isn't Mine");
                return false;
            }
        }
        System.out.println("It is Mine");
        return true;
    }

    public boolean IsItBroad(byte[] input) {
        for (int i = 0; i < enet_frame.Address_Size; i++) {
            if (input[i] == (byte) 0xff) //목적지이더넷주소가 자신의이더넷주소가아니면 false와 break
                continue;
            else {
                System.out.println("It isn't Broad");
                return false;
            }
        }
        System.out.println("It is Broad");
        return true;
    }

    public boolean IsItMyPacket(byte[] input) {
        for (int i = 0; i < enet_frame.Address_Size; i++) {
            if (enet_frame.enet_srcaddr.addr[i] == input[i + enet_frame.Address_Size]) //목적지이더넷주소가 자신의이더넷주소가아니면 false와 break
                continue;
            else {
                System.out.println("It isn't MyPacket");
                return false;
            }
        }
        System.out.println("It is MyPacket");
        return true;
    }

    public synchronized boolean Receive(byte[] input) {
        System.out.println("Ethernet_Receive");

        boolean MyPacket, Mine, Broadcast;
        MyPacket = IsItMyPacket(input);
        if (MyPacket == true) {
            return false;
        } else {//내 패킷이 아닐 경우
            Broadcast = IsItBroad(input);
            if (Broadcast == false) {
                Mine = IsItMine(input);
                if (Mine == false) { //목적지 이더넷 주소가 내 주소가 아닐때
                    return false;
                }
            }
        }
        byte data[];
        data = RemoveCappHeader(input, input.length);
        this.GetUpperLayer(1).Receive(data); //0번이 IP, 1번이 ARP라고 생각해서 ARP로 올리기 위해서 1로 설정함.
        return true;

    }

    public byte[] GetSrcAdd() {
        byte[] k = new byte[6];
        for (int i = 0; i < this.enet_frame.enet_srcaddr.addr.length; i++) {
            k[i] = enet_frame.enet_srcaddr.addr[i];
        }
        return k;
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