package ARP;

import java.util.ArrayList;

public class ARPLayer implements BaseLayer {
   public int nUpperLayerCount = 0;
   public String pLayerName = null;
   public BaseLayer p_UnderLayer = null;
   public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

   final static int ARP_MAC_TYPE = 2;
   final static int ARP_IP_TYPE = 2;
   final static int ARP_LEN_MAC_VALUE = 6;
   final static int ARP_LEN_IP_VALUE = 4;
   final static int OPCODE = 2;
   final static int ASK = 1;
   final static int REQUEST = 2;
   final static int INCOMPLETE = 0;
   final static int COMPLETE = 1;


   private class _ARP_MAC_ADDR {
      //ARP용 MAC Address
      private byte[] addr = new byte[6];

      public _ARP_MAC_ADDR() {
         this.addr[0] = (byte) 0x00;
         this.addr[1] = (byte) 0x00;
         this.addr[2] = (byte) 0x00;
         this.addr[3] = (byte) 0x00;
         this.addr[4] = (byte) 0x00;
         this.addr[5] = (byte) 0x00;
      }

   }

   private class _ARP_IP_ADDR {
      //ARP용 IP Address
      private byte[] addr = new byte[4];

      public _ARP_IP_ADDR() {
         this.addr[0] = (byte) 0x00;
         this.addr[1] = (byte) 0x00;
         this.addr[2] = (byte) 0x00;
         this.addr[3] = (byte) 0x00;
      }

   }

   private class _ARP_FRAME {

      byte[] macType;
      byte[] ipType;
      byte lenMacAddr;
      byte lenIpAddr;
      byte[] opCode;
      _ARP_MAC_ADDR mac_sendAddr;
      _ARP_MAC_ADDR mac_recvAddr;
      _ARP_IP_ADDR ip_sendAddr;
      _ARP_IP_ADDR ip_recvAddr;

      public _ARP_FRAME() {
         macType = new byte[ARP_MAC_TYPE];
         ipType = new byte[ARP_IP_TYPE];
         lenMacAddr = 0;
         lenIpAddr = 0;
         opCode = new byte[OPCODE];
         mac_sendAddr = new _ARP_MAC_ADDR();
         mac_recvAddr = new _ARP_MAC_ADDR();
         ip_sendAddr = new _ARP_IP_ADDR();
         ip_recvAddr = new _ARP_IP_ADDR();
      }

   }

   //ARP 안에 들어가는 데이터
   _ARP_FRAME ARP_Header = new _ARP_FRAME();

   //테이블
   ArrayList<CacheData> cacheTable = new ArrayList<>();
   
   //생성자
   public void ARPLayer(String pName) {
      pLayerName = pName;
      ResetHeader();
   }

   //헤더 초기화
   public void ResetHeader() {
      
      ARP_Header.macType= intToByte4(1);
      ARP_Header.ipType = intToByte4(0x0800);
      ARP_Header.lenMacAddr = (byte)ARP_LEN_MAC_VALUE;
      ARP_Header.lenIpAddr = (byte)ARP_LEN_IP_VALUE;
      
      for (int i = 0; i < 6; i++) {
         ARP_Header.mac_sendAddr.addr[i] = (byte) 0x00;
         ARP_Header.mac_recvAddr.addr[i] = (byte) 0x00;
         ARP_Header.ip_sendAddr.addr[i] = (byte) 0x00;
         ARP_Header.ip_recvAddr.addr[i] = (byte) 0x00;
      }

      for (int i = 0; i < 4; i++) {
         ARP_Header.ip_sendAddr.addr[i] = (byte) 0x00;
         ARP_Header.ip_recvAddr.addr[i] = (byte) 0x00;
      }
   }

   public boolean Send(byte[] input, int length) {
      //들어온 input(dstIp, srcIP)를 분리하여 IP주소를 얻어냄 
      //앞의 4바이트는 dst, 뒤의 4바이트는 src
      _ARP_IP_ADDR dstIpAddr = new _ARP_IP_ADDR();
      _ARP_IP_ADDR srcIpAddr = new _ARP_IP_ADDR();
      System.arraycopy(input, 0, dstIpAddr.addr, 0, 4); //arraycopy로 dst addr가져옴
      System.arraycopy(input, 4, srcIpAddr.addr, 0, 4); //src addr
      //send용 ARPHeader를 호출
      addSendARPHeader(dstIpAddr, srcIpAddr);
      
      //캐쉬 테이블에 올리는 부분 구현 해야함
      
      //Ethernet.send를 호출하는 부분 구현 해야함

      return true;
   }

   public boolean Receive(byte[] input) {
      //opCode가 1인 경우와 opCode가 2인 경우를 구분
      
      //opCode가 1인 경우
      //(여기까지 올라왔다면 내 mac주소를 삽입한 다음 데이터를 보낸 상대의 주소를 해쉬 테이블에 업데이트, 그 다음 스와핑하여 다시 보냄)
      // 1.내 맥 주소를  receiver 칸에 삽입
      // 2. sender의 정보를 추출
      // 3. 헤더를 붙임(헤더에서 스와핑시킴)
      // 4. 캐시 테이블 업데이트 (sender의 정보를 업데이트)
      // 5. 헤더를 붙인 데이터를 하위 레이어의 send로 전송
      
      //opCode가 2인 경우
      //(원하는 정보를 얻은 것이므로 원하는 정보를 추출하여 해쉬 테이블을 업데이트 함)
      // 1. sender부분의 mac주소가 우리가 알고 싶었던 주소 -> 추출
      // 2. 주소를 캐시 테이블에 업데이트 
      
      //먼저 input에서 opCode인 부분을 int 형태로 바꿈
      int opCode = byte2ToInt(input[6], input[7]);
      
      // 1인지 2인지 확인
      if(opCode == ASK) {
         // 1인 경우
         
         _ARP_MAC_ADDR recvMacAddr = null; //특정한 함수를 받아서 Mac주소를 받음 (미리 받아놓거나 함, 논의 필요)
         
         System.arraycopy(recvMacAddr.addr, 0, input, 18, 6);
         
         //sender Mac, Ip
         _ARP_MAC_ADDR senderMac = new _ARP_MAC_ADDR();
         _ARP_IP_ADDR senderIp = new _ARP_IP_ADDR();

         System.arraycopy(input, 8, senderMac.addr, 0, 6);
         System.arraycopy(input, 14, senderIp.addr, 0, 4);
         
         //sender의 정보가 이제는 receiver가 되고 receiver의 정보가 sender의 정보가 된다.
         addReceiveHeader(input);
         
         //캐시 테이블을 업데이트 구현 해야함
         
         //Ethernet send로 헤더를 붙인 데이터 전송을 구현해야함
         
      }
      else {
         // opcode가 2인 경우
         //(상대방 쪽에서 보내온 것이 sender이므로 sender의 mac이 중요)
         _ARP_MAC_ADDR senderMac = new _ARP_MAC_ADDR();
         
         for(int i = 0; i < 6; i++) {
            senderMac.addr[i] = input[8+i];
         }
         
         //이제 주소를 캐쉬 테이블에 업데이트하는 함수 구현
         
      }
      return true;
   }

   //헤더를 추가하는 부분
   public void addSendARPHeader(_ARP_IP_ADDR dstIpAddr, _ARP_IP_ADDR srcIpAddr) {
      ARP_Header.opCode = intToByte2(ASK);
      ARP_Header.ip_sendAddr= srcIpAddr; //맞는지 확인
      //ARP_Header.mac_sendAddr ;//앱에서 mac주소 받음 =>받아오는 함수
      ARP_Header.ip_recvAddr = dstIpAddr;
      //내 맥주소 관련 부분 따로 상의
      //내 소스의 mac주소는 나중에 따로 초기화하든지 해야함
      //목적지의 mac 주소는 이미 reset에서 0으로 설정   
   }
   
   //receive용 header(opCode = 1을 받았을 경우)
   public void addReceiveHeader(byte[] input) {
      
      ARP_Header.opCode = intToByte2(REQUEST);
      //현재 input의 seder위치가 receiver로 옮겨지고 receiver의 위치가 sender의 위치로 옮겨짐
      System.arraycopy(input, 8, ARP_Header.mac_recvAddr.addr, 0, 6);
      System.arraycopy(input, 14, ARP_Header.ip_recvAddr.addr, 0, 4);
      System.arraycopy(input, 18, ARP_Header.mac_sendAddr.addr, 0, 6);
      System.arraycopy(input, 14, ARP_Header.ip_sendAddr.addr, 0, 4);
      
   }

   //캐쉬 테이블에 변경
   public void changeCache() {

   }

   byte[] intToByte2(int value) { //정수형을 byte 2배열로 바꿈.
      byte[] temp = new byte[2];
      temp[1] = (byte) (value >> 8);
      temp[0] = (byte) value;

      return temp;
   }
   
   int byte2ToInt(byte one0, byte two1) {
      int number = (one0 & 0xFF) | ((two1 & 0xFF ) << 8);
      return number;
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
   public String GetLayerName() {
      // TODO Auto-generated method stub
      return pLayerName;
   }

   @Override
   public BaseLayer GetUnderLayer() {
      // TODO Auto-generated method stub
      if(p_UnderLayer==null)
         return null;
      return p_UnderLayer;
   }

   @Override
   public BaseLayer GetUpperLayer(int nindex) {
      // TODO Auto-generated method stub
      if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
         return null;
      return p_aUpperLayer.get(nindex);
   }

   @Override
   public void SetUnderLayer(BaseLayer pUnderLayer) {
      // TODO Auto-generated method stub
      if (pUnderLayer == null)
         return;
      this.p_UnderLayer = pUnderLayer;

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
   public void SetUpperUnderLayer(BaseLayer pUULayer) {
      // TODO Auto-generated method stub
      this.SetUpperLayer(pUULayer);
      pUULayer.SetUnderLayer(this);
   }

   class CacheData{
      private _ARP_MAC_ADDR macAddr;
      private _ARP_IP_ADDR ipAddr;
      private int status;

      public CacheData(_ARP_MAC_ADDR newMac, _ARP_IP_ADDR newIp, int newStatus) {
         this.macAddr = newMac;
         this.ipAddr = newIp;
         this.status = newStatus;
      }

      public void setMacAddr(_ARP_MAC_ADDR givenMac) {
         this.macAddr = givenMac;
      }

      public void setIpAddr(_ARP_IP_ADDR givenIp) {
         this.ipAddr = givenIp;
      }

      public void setStatus(int givenStatus) {
         this.status = givenStatus;
      }

      public _ARP_MAC_ADDR getMacAddr() {
         return this.macAddr;
      }

      public _ARP_IP_ADDR getIpAddr() {
         return this.ipAddr;
      }

      public int getStatus() {
         return this.status;
      }
   }

}
