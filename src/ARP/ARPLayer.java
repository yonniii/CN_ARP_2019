package ARP;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;

public class ARPLayer implements BaseLayer {
   public int nUpperLayerCount = 0;
   public int nUnderLayerCount = 0;
   public String pLayerName = null;
   public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
   public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

   final static int HEADER_SIZE = 28;

   final static int ARP_MAC_TYPE = 2;
   final static int ARP_IP_TYPE = 2;
   final static int ARP_LEN_MAC_VALUE = 6;
   final static int ARP_LEN_IP_VALUE = 4;
   final static int OPCODE = 2;
   final static int ASK = 1;
   final static int REQUEST = 2;
   final static int INCOMPLETE = 0;
   final static int COMPLETE = 1;
   final static int INVALID = 2;//CHANGE 이거 애플리케이션에서 문자열 띄워주게하기


   // 3ACK를 확인하기 위한 변수 (receive가 왔는지 확인)
   boolean checkReceive = false;

    // 3ACK일 경우 true가 되는 변수
   boolean check3ACK = false;

   //캐시테이블에 들어올 때 데이터 구분용 index
   int cacheCount = 0;


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
      byte[]lenMacAddr;
      byte[] lenIpAddr;
      byte[] opCode;
      _ARP_MAC_ADDR mac_sendAddr;
      _ARP_MAC_ADDR mac_recvAddr;
      _ARP_IP_ADDR ip_sendAddr;
      _ARP_IP_ADDR ip_recvAddr;

      public _ARP_FRAME() {
         macType = new byte[ARP_MAC_TYPE];
         ipType = new byte[ARP_IP_TYPE];
         lenMacAddr = new byte[1];
         lenIpAddr = new byte[1];
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
   ArrayList<CacheData> cacheTable;
   ArrayList<ProxyData> proxyTable;

   //자신의 MAC 주소
   byte[] myMacAddr = new byte[ARP_LEN_MAC_VALUE];
   //자신의 IP 주소
   byte[] myIpAddr = new byte[ARP_LEN_IP_VALUE];
   //GARP용 MAC주소
   byte[] myGrtAddr = new byte[ARP_LEN_MAC_VALUE];

   //하드웨어 주소를 변경할 때 변경한다는 것을 확인하는 함수
   boolean changeMac = false;
   boolean ipCollision = false; //CHANGE ip충돌 감지 변수

    //생성자
   public ARPLayer(String pName) {
      pLayerName = pName;
      ResetHeader();
      cacheTable = new ArrayList<>();
      proxyTable = new ArrayList<>();
   }

   public byte[] getaddr(_ARP_IP_ADDR d){
      return d.addr;
   }

   //헤더 초기화
   public void ResetHeader() {

      ARP_Header.macType= intToByte2(1);
      ARP_Header.ipType = intToByte2(0x0800);
      ARP_Header.lenMacAddr[0] = (byte)ARP_LEN_MAC_VALUE;
      ARP_Header.lenIpAddr[0] = (byte)ARP_LEN_IP_VALUE;

      for (int i = 0; i < 6; i++) {
         ARP_Header.mac_sendAddr.addr[i] = (byte) 0x00;
         ARP_Header.mac_recvAddr.addr[i] = (byte) 0x00;
      }

      for (int i = 0; i < 4; i++) {
         ARP_Header.ip_sendAddr.addr[i] = (byte) 0x00;
         ARP_Header.ip_recvAddr.addr[i] = (byte) 0x00;
      }
   }
   public ArrayList<CacheData> getCacheTable(){
      return this.cacheTable;
   }

   // 받아온 byte[]의 mac주소를 내 myMacAddr에 저장하는 함수
   public void setMacAddress(byte[] input) {
      System.arraycopy(input, 0, myMacAddr, 0, ARP_LEN_MAC_VALUE);
   }

   // 받아온 bytep[]의 ip주소를  내 myIpAddr에 저장하는 함수
   public void setIpAddress(byte[] input) {
      System.arraycopy(input, 0, myIpAddr, 0, ARP_LEN_IP_VALUE);
   }

    //gratuitous일 때 app에서 true값과 주소값을 넣어줌
   public void setGrt(boolean input, byte[] setGrtAddr) {
      changeMac = input;
      System.arraycopy(setGrtAddr, 0, myGrtAddr, 0, ARP_LEN_MAC_VALUE);
   }

   public boolean chatSend(byte[] input, int length) {
      //dstIP의 주소 추출
      byte[] dstIpAddr = new byte[ARP_LEN_IP_VALUE];

      //arraycopy로 dst ip주소 추출
      System.arraycopy(input, 12, dstIpAddr, 0, ARP_LEN_IP_VALUE);

      //dstIp에 해당하는 MAC (없으면 null)
      byte[] dstMacAddr = new byte[ARP_LEN_MAC_VALUE];

      //dst용 반환 index값
      int dstIndex = searchCacheTable(dstIpAddr);

      if(dstIndex != -1){
          //그냥 dst 찾아가지고 ethernet에 send를 보낸다.
         System.arraycopy(cacheTable.get(dstIndex).macAddr, 0, dstMacAddr, 0, ARP_LEN_MAC_VALUE);

         //찾으면 ethernet에 박아줌
         ((EthernetLayer)this.GetUnderLayer(0)).setDstAddr(dstMacAddr);

         //이더넷 샌드로 보냄
         ((EthernetLayer)this.GetUnderLayer(0)).ChatFileSend(input, input.length);

      }
      else {

         //테이블에 없을 경우
         ARPSend(input, input.length);
         
         try {
            Thread.sleep(500);
         } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         }

         new Thread(() -> {

            while(true) {
               //캐쉬 테이블 검색 -> 없으면 그냥 반복문 재생
               //있으면 dst박아주고 send한 다음 return

               try {
                  Thread.sleep(500);
               } catch (InterruptedException e) {
                  // TODO Auto-generated catch block
                  e.printStackTrace();
               }

               int index = searchCacheTable(dstIpAddr);

               if(index != -1) {
                  return;
               }
            }
         }).start();
         
         dstIndex = searchCacheTable(dstIpAddr);
         
         System.arraycopy(cacheTable.get(dstIndex).macAddr, 0, dstMacAddr, 0, ARP_LEN_MAC_VALUE);

          //찾으면 ethernet에 박아줌
         ((EthernetLayer)this.GetUnderLayer(0)).setDstAddr(dstMacAddr);

         //이더넷 샌드로 보냄
         ((EthernetLayer)this.GetUnderLayer(0)).ChatFileSend(input, input.length);


         return true;
      }

      return false;
   }

   public int searchCacheTable(byte[] inputIp) {

      for(int i = 0; i < cacheTable.size(); i++) {
         if(Arrays.equals(cacheTable.get(i).ipAddr, inputIp)) {
            return i;
         }
      }
      return -1;
   }


   public boolean Send(byte[] input, int length) {
      //check send
       // basic,proxy인지, gratuitous인지  확인
      if(changeMac == true) {
         //gratuitous일 경우
         GARPSend(input, length);
      }
      else {
         //basic, proxy일 경우
         ARPSend(input, length);
      }
      return true;

   }

   public boolean ARPSend(byte[] input, int length) {

      byte[] dstIpAddr = new byte[ARP_LEN_IP_VALUE];
      byte[] srcIpAddr = new byte[ARP_LEN_IP_VALUE];

      System.arraycopy(this.myIpAddr, 0, srcIpAddr, 0, ARP_LEN_IP_VALUE);

      // srcIp는 내가 이미 가지고 있음
           // dstIp는 input의 12byte부터 4바이트
      dstIpAddr = new byte[ARP_LEN_IP_VALUE];

      // arraycopy로 dst ip주소 추출
      System.arraycopy(input, 12, dstIpAddr, 0, ARP_LEN_IP_VALUE);

      // send용 ARPHeader세팅
      sendARPHeader(dstIpAddr, srcIpAddr);

      // input 앞에 ARP헤더를 붙여서 byte[]로 나타냄
      // ethernet.send로 보낼 데이터
      byte[] sendData = addHeader(ARP_Header, input);

      byte[] cacheMac = new byte[ARP_LEN_MAC_VALUE];
      byte[] cacheIp = new byte[ARP_LEN_IP_VALUE];

      System.arraycopy(ARP_Header.mac_recvAddr.addr, 0, cacheMac, 0, ARP_LEN_MAC_VALUE);
      System.arraycopy(ARP_Header.ip_recvAddr.addr, 0, cacheIp, 0, ARP_LEN_IP_VALUE);

      // 캐쉬 테이블에 올리는 부분
      addCache(new CacheData(cacheCount, cacheMac, cacheIp, INCOMPLETE));

      ARPSend_Thread thread = new ARPSend_Thread(sendData, (EthernetLayer)this.GetUnderLayer(0));
      Thread obj = new Thread(thread);
      obj.start();

      try {
         Thread.sleep(20000);
      } catch (InterruptedException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }

      obj.interrupt();
      ResetHeader();

      //send가 끝났을 때 3ACk가 발동한 경우 table에 status를 invalid로 바꿈
      if(check3ACK == true) {
         check3ACK = false;
         changeCache(cacheMac, cacheIp, INVALID);
      }

      return true;
   }

   class ARPSend_Thread implements Runnable {
      byte[] sendData;
      EthernetLayer ethernetLayer;

      public ARPSend_Thread(byte[] input, EthernetLayer ethernetLayer) {
         this.sendData = input;
         this.ethernetLayer = ethernetLayer;
      }

      @Override
      public void run() {

          // 1번 보낸다
         this.ethernetLayer.BroadSend(sendData, sendData.length);

         try {
            Thread.sleep(5000);
         } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
         }

         //이미 위에서 1번 보냈기 때문에 2번까지 가능하다
         for(int count = 0; count < 2; count++) {
            
            //30초 쉰 뒤에 receive가 왔는지 확인
            if(checkReceive == true) {
               //만약 왔으면 바깥으로 나감

               checkReceive = false;
               return;
            }

            //만약 오지 않았을 경우 다시 보냄
            this.ethernetLayer.BroadSend(sendData, sendData.length);

            //30초 동안 쉼
            try {
               Thread.sleep(5000);
            } catch (InterruptedException e) {
               // TODO Auto-generated catch block
               e.printStackTrace();
            }
         }

         //3번 보내고 마지막 확읜 경우 checkReceive가 true면 receive를 받음
         if(checkReceive == true) {
            checkReceive = false;
            return;
         }
         else {
            //오지 않았을 경우에는 3ACK 발동
            check3ACK = true;
            return;
         }

      }
   }

   public boolean GARPSend(byte[] input, int length) {
      byte[] dstIpAddr = new byte[ARP_LEN_IP_VALUE];
      byte[] srcIpAddr = new byte[ARP_LEN_IP_VALUE];

      System.arraycopy(this.myIpAddr, 0, srcIpAddr, 0, ARP_LEN_IP_VALUE);

      changeMac = false;

      // dstIp와 srcIp는 같음
      System.arraycopy(this.myIpAddr, 0, dstIpAddr, 0, ARP_LEN_IP_VALUE);

      // send용 ARPHeader세팅
      sendARPHeader(dstIpAddr, srcIpAddr);

      // input 앞에 ARP헤더를 붙여서 byte[]로 나타냄
      // ethernet.send로 보낼 데이터
      byte[] sendData = addHeader(ARP_Header, input);

       // Ethernet.send를 호출하는 부분
      ((EthernetLayer) this.GetUnderLayer(0)).BroadSend(sendData, sendData.length);

      ResetHeader();
      return true;
   }




    //들어온 ip와 같은 인덱스가 존재할 경우 인덱스의 mac주소를 리턴
   public byte[] isProxy(byte[] recvIpAddr) {
      for(int i = 0; i < proxyTable.size(); i++) {

         for(int j = 0; j < proxyTable.get(i).ipAddr.length; j++) {
            if(Arrays.equals(proxyTable.get(i).ipAddr, recvIpAddr)) {
               return proxyTable.get(i).macAddr;
            }
         }
      }
      return null;
   }

   public boolean Receive(byte[] input) {
      //opCode가 1인 경우와 opCode가 2인 경우를 구분

            //opCode가 1인 경우
            //gratuitous인지 proxy인지 basic인지 버리는 것인지 결정젙

       //opCode가 2인 경우
           //(원하는 정보를 얻은 것이므로 원하는 정보를 추출하여 해쉬 테이블을 업데이트 함)
            // 1. sender부분의 mac주소가 우리가 알고 싶었던 주소 -> 추출
            // 2. 주소를 캐시 테이블에 업데이트

      //먼저 input에서 opCode인 부분을 int 형태로 바꿈
      int opCode = byte2ToInt(input[6], input[7]);

      // 1인지 2인지 확인
      if(opCode == ASK) {
         // 1인 경우
          //gratuitous인 경우인지 확인

         //target ip 주소 추출
         byte[] recvIpAddr = new byte[ARP_LEN_IP_VALUE];
         System.arraycopy(input, 24, recvIpAddr, 0, ARP_LEN_IP_VALUE);

         //sender ip 주소 추출
         byte[] sendIpAddr = new byte[ARP_LEN_IP_VALUE];
         System.arraycopy(input, 14, sendIpAddr, 0, ARP_LEN_IP_VALUE);

         //먼저 sender의 ip와 target의 ip가 같은지 확인
         if(Arrays.equals(sendIpAddr, recvIpAddr)) {
            //gratuitous인 경우
            //내 ip주소와 sender에 담긴 ip주소가 같을 경우
            if(Arrays.equals(myIpAddr, sendIpAddr)) {
               //ip충돌이 일어났다고 생각
               //senderMac에 자신의 MAC를 덮어씌움
               System.arraycopy(myMacAddr, 0, input, 8, ARP_LEN_MAC_VALUE);

               //덮어씌운 input의 opCode를 2로 바꿈
               byte[] tempOp = intToByte2(REQUEST);
               System.arraycopy(tempOp, 0, input, 6, OPCODE);

               //변경한 inputData를 하위 레이어로 전송
               ((EthernetLayer)this.GetUnderLayer(0)).BroadSend(input, input.length);

            }

            //sender의 맥주소 추출
            byte[] sendMacAddr = new byte[ARP_LEN_MAC_VALUE];
            System.arraycopy(input, 8, sendMacAddr, 0, ARP_LEN_MAC_VALUE);

            //추출한 sender의 맥과 아이피 주소를 추가
            changeCache(sendMacAddr, sendIpAddr, COMPLETE);

            ResetHeader();

            return true;
         }
          //basic, proxy 또는 자신과 관련없는 패킷인 경우
         else {

             // target의 ip주소가 자신의 ip주소와 같은지 확인(basic,proxy 아니면 자신과 관련 없는 패킷)
            if(Arrays.equals(recvIpAddr, myIpAddr)) {
               //같다면 basic arp
               //자신의 맥 주소를 추출해서 input의 target.mac부분에 삽입
               byte[] myMac = new byte[ARP_LEN_MAC_VALUE];
               System.arraycopy(myMacAddr, 0, myMac, 0, ARP_LEN_MAC_VALUE);
               System.arraycopy(myMac, 0, input, 18, ARP_LEN_MAC_VALUE);
            }
            else {
               //다를 경우 1. proxy, 2. 그냥 잘못 온 경우

               //추출한 주소를 가지고 proxy용 recvMac을 구함 (없으면 null)
               byte[] proxyRecvMacAddr = isProxy(recvIpAddr);

               if(proxyRecvMacAddr != null) { //Proxy
                  //원래 target.mac의 위치에 넣어줌
                  System.arraycopy(proxyRecvMacAddr, 0, input, 18, ARP_LEN_MAC_VALUE);
               }
               else {
                  //아닐 경우 sender의 정보만 빼서 저장하고 버림

                  //sender Mac, Ip
                  byte[] senderMac = new byte[ARP_LEN_MAC_VALUE];
                  byte[] senderIp = new byte[ARP_LEN_IP_VALUE];

                  System.arraycopy(input, 8, senderMac, 0, ARP_LEN_MAC_VALUE);
                  System.arraycopy(input, 14, senderIp, 0, ARP_LEN_IP_VALUE);

                  //sender의 정보는 다 있기 때문에 테이블에 추가
                  addCache(new CacheData(cacheCount, senderMac, senderIp, COMPLETE));

                  ResetHeader();

                  return false;
               }
            }

            //sender Mac, Ip
            byte[] senderMac = new byte[ARP_LEN_MAC_VALUE];
            byte[] senderIp = new byte[ARP_LEN_IP_VALUE];

            System.arraycopy(input, 8, senderMac, 0, ARP_LEN_MAC_VALUE);
            System.arraycopy(input, 14, senderIp, 0, ARP_LEN_IP_VALUE);

            //sender의 정보는 다 있기 때문에 테이블에 추가
            addCache(new CacheData(cacheCount, senderMac, senderIp, COMPLETE));

            //sender의 정보가 이제는 receiver가 되고 receiver의 정보가 sender의 정보가 된다.
            //헤더를 세팅해줌
            receiveHeader(input);

             //헤더를 제외한 뒤의 데이터 부분만 추출함
            byte[] realInput = new byte[input.length-28];
            System.arraycopy(input, 28, realInput, 0, input.length-28);

            //세팅한 헤더를 데이터에 붙임
            //세팅된 헤더 + 뒷 부분의 진짜 데이터
            byte[] sendData = addHeader(ARP_Header, realInput);

            //Ethernet send로 헤더를 붙인 데이터 전송을 구현해야함
            ((EthernetLayer)this.GetUnderLayer(0)).Send(sendData, sendData.length); //CHANGE

         }
      }
       // opcode가 2인 경우
      else {
         checkReceive = true;
         //gratuitous의 ip충돌로 온 것인지 아니면 basic나 proxy로 온 것인지 확인 필요

         //senderIP랑 targetIP를 추출
         byte[] senderIp = new byte[ARP_LEN_IP_VALUE];
         byte[] recvIp = new byte[ARP_LEN_IP_VALUE];
         System.arraycopy(input, 14, senderIp, 0, ARP_LEN_IP_VALUE);
         System.arraycopy(input, 24, recvIp, 0, ARP_LEN_IP_VALUE);

         //sender의 mac주소 추출
         byte[] senderMac = new byte[ARP_LEN_MAC_VALUE];
         System.arraycopy(input, 8, senderMac, 0, ARP_LEN_MAC_VALUE);

         //senderIp랑 targetIp가 같은 경우 ip충돌
         if(Arrays.equals(senderIp, recvIp)) {
            //ip 충돌이 일어났을 경우
            //내가 보낸 GARP에 대한 ip충돌인지 아니면 다른 호스트에서 일어난 ip충돌인지 확인
            //내 ip랑 sender의 ip가 같으면 내가 보낸 gARP가 충돌한 것
            if(Arrays.equals(myIpAddr, senderIp)) {
               //어플리케이션과 연결하여 오류 메세지 띄움
               IPCollision();
            }
            else {
               //다른 호스트에서 일어난 일일 경우
                          //테이블을 수정
               changeCache(senderMac, senderIp, COMPLETE);

               new Thread(() -> {
                  try {
                     Thread.sleep(50);
                  } catch (InterruptedException e) {
                     // TODO Auto-generated catch block
                     e.printStackTrace();
                  }
               }).start();

            }
         }
         else {
            //basic나 proxy일 경우
            changeCache(senderMac, senderIp, COMPLETE);
         }
      }

      ResetHeader();

      return true;
   }


   //헤더를 추가하는 부분
   public void sendARPHeader(byte[] dstIpAddr, byte[] srcIpAddr) {
      //op코드 1로 설정
      ARP_Header.opCode = intToByte2(ASK);

      //헤더에 설정할 sender의 맥주소용 변수
      byte[] useMyMac = new byte[ARP_LEN_MAC_VALUE];

      //이때 GARP인지 그냥 ARP인지 확인
      if(Arrays.equals(srcIpAddr, dstIpAddr)) {
         //같으면 GARP
                //GARP변수에서 MAC값을 가져옴
         System.arraycopy(myGrtAddr, 0, useMyMac, 0, ARP_LEN_MAC_VALUE);
      }
      else {
         //다르면 PROXY or BASIC
         //내 MAC주소를 가져옴
         System.arraycopy(myMacAddr, 0, useMyMac, 0, ARP_LEN_MAC_VALUE);
      }

      //useMyMac의 값을 헤더에 삽입
      System.arraycopy(useMyMac, 0, ARP_Header.mac_sendAddr.addr, 0, ARP_LEN_MAC_VALUE);

      //나머지 IP값을 설정
      System.arraycopy(srcIpAddr, 0, ARP_Header.ip_sendAddr.addr, 0, ARP_LEN_IP_VALUE);
      System.arraycopy(dstIpAddr, 0, ARP_Header.ip_recvAddr.addr, 0, ARP_LEN_IP_VALUE);

   }

   //receive용 header(opCode = 1을 받았을 경우)
   public void receiveHeader(byte[] input) {

      ARP_Header.opCode = intToByte2(REQUEST);

      //현재 input의 seder위치가 receiver로 옮겨지고 receiver의 위치가 sender의 위치로 옮겨짐
      System.arraycopy(input, 8, ARP_Header.mac_recvAddr.addr, 0, ARP_LEN_MAC_VALUE);
      System.arraycopy(input, 14, ARP_Header.ip_recvAddr.addr, 0, ARP_LEN_IP_VALUE);
      System.arraycopy(input, 18, ARP_Header.mac_sendAddr.addr, 0, ARP_LEN_MAC_VALUE);
      System.arraycopy(input, 24, ARP_Header.ip_sendAddr.addr, 0, ARP_LEN_IP_VALUE);

   }

   public byte[] addHeader(_ARP_FRAME ARP_Header, byte[] input) {
      //ARP_Header 다음 input 데이터를 byte[]에 붙임
      byte[] returnData = new byte[HEADER_SIZE + input.length];

      //헤더 이동
      System.arraycopy(ARP_Header.macType, 0, returnData, 0, 2);
      System.arraycopy(ARP_Header.ipType, 0, returnData, 2, 2);
      System.arraycopy(ARP_Header.lenMacAddr, 0, returnData, 4, 1);
      System.arraycopy(ARP_Header.lenIpAddr, 0, returnData, 5, 1);
      System.arraycopy(ARP_Header.opCode, 0, returnData, 6, 2);
      System.arraycopy(ARP_Header.mac_sendAddr.addr, 0, returnData, 8, 6);
      System.arraycopy(ARP_Header.ip_sendAddr.addr, 0, returnData, 14, 4);
      System.arraycopy(ARP_Header.mac_recvAddr.addr, 0, returnData, 18, 6);
      System.arraycopy(ARP_Header.ip_recvAddr.addr, 0, returnData, 24, 4);

      //데이터 이동
      System.arraycopy(input, 0, returnData, 28, input.length);

      return returnData;
   }

    //캐쉬 테이블에 데이터를 추가하는 경우
   public void addCache(CacheData givenData) {
      //Ip addr을 기준으로 찾아서 추가

      int check = 0;
      for(int i = 0; i < cacheTable.size(); i++) {
         if(Arrays.equals(cacheTable.get(i).getIpAddr(),givenData.getIpAddr())) {
            check = 1; //이미 있는 경우
            return;
         }
      }
      if(check != 1) { //테이블에 매개변수의 ip가 없는 경우
         cacheTable.add(givenData);

         //캐시쓰레드에  해당 데이터의 status, 이 데이터가 들어간 인덱스 값을 매개변수로 넘겨줌(status상태에 따라 20분, 3분동안 저장)
         cacheThread(givenData.status, cacheCount);

          //캐시 데이터 인덱스 증가
         cacheCount++;
      }
   }

   public void cacheThread(int status, int cacheIndex) {
      Timer cacheTimer = new Timer();

      TimerTask removeCache = new TimerTask() {
         @Override
         public void run() {
            //같은 cacheIndex를 가지는 데이터를 찾음
            //있으면 삭제, 없으면 그냥 둠
            for(int i = 0; i < cacheTable.size(); i++) {
               if(cacheTable.get(i).cacheCount == cacheIndex) {
                  cacheTable.remove(i);
                  return;
               }
            }
         }
      };

      //여기서 status 상태를 보고 data의 삭제 시간을 결정
      //incomplete일 경우 3분, complete일 경우 20분 (1초에 1000)
      if(status == COMPLETE)
         //1200000
         cacheTimer.schedule(removeCache, 1200000);
      else
         //180000
         cacheTimer.schedule(removeCache, 180000);
   }

   //프록시 테이블에 데이터를 추가하는 경우
   public void addProxy(byte[] givenIp, byte[] givenMac, String givenName) {

      //ProxyTable에 추가
      proxyTable.add(new ProxyData(givenMac, givenIp, givenName));

   }


   //캐쉬 테이블의 데이터를 complete로 변경
   public void changeCache(byte[] sendMac, byte[] sendIp, int status) {
      //Ip addr을 기준으로 찾아서 추가
      for(int i = 0; i < cacheTable.size(); i++) {
         if(Arrays.equals(cacheTable.get(i).getIpAddr(), sendIp)) {

            //값을 변경함
            System.arraycopy(sendMac, 0, cacheTable.get(i).macAddr, 0, ARP_LEN_MAC_VALUE);
            cacheTable.get(i).status = status;

            cacheThread(cacheTable.get(i).status, cacheTable.get(i).cacheCount);

            return;
         }
      }
   }


    //가장 마지막으로 들어온 값 삭제
   public void deleteCache() {
      cacheTable.remove(cacheTable.size()-1);
   }

   //전체 cacheTable 삭제
   public void deleteAllCache() {
      cacheTable.clear();
   }

   //가장 마지막으로 들어온 값 삭제
   public void deleteProxy() {
      proxyTable.remove(proxyTable.size()-1);
   }

   //ip 충돌이 일어난 경우 하위 레이어인 이더넷으로 전달하여 상위 레이어인 IP로 보낸다
   public boolean IPCollision(){
      ((EthernetLayer) this.GetUnderLayer(0)).IPCollision();
      return true;
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

   class CacheData{
      private int cacheCount;
      private byte[] macAddr;
      private byte[] ipAddr;
      private int status;

      public CacheData(int cacheCount, byte[] cacheMac, byte[] cacheIp, int newStatus) {
         this.cacheCount = cacheCount;
         this.macAddr = cacheMac;
         this.ipAddr = cacheIp;
         this.status = newStatus;
      }

      public void setMacAddr(byte[] givenMac) {
         this.macAddr = givenMac;
      }

      public void setIpAddr(byte[] givenIp) {
         this.ipAddr = givenIp;
      }

      public void setStatus(int givenStatus) {
         this.status = givenStatus;
      }

      public byte[] getMacAddr() {
         return this.macAddr;
      }

      public byte[] getIpAddr() {
         return this.ipAddr;
      }

      public int getStatus() {
         return this.status;
      }
   }

   class ProxyData {
      private byte[] macAddr;
      private byte[] ipAddr;
      private String deviceName;


      public ProxyData(byte[] newMac, byte[] newIp, String newName) {
         this.macAddr = newMac;
         this.ipAddr = newIp;
         this.deviceName = newName;
      }

      public void setMacAddr(byte[] givenMac) {
         this.macAddr = givenMac;
      }

      public void setIpAddr(byte[] givenIp) {
         this.ipAddr = givenIp;
      }

      public void setDeviceName(String givenName) {
         this.deviceName = givenName;
      }

      public byte[] getMacAddr() {
         return this.macAddr;
      }

      public byte[] getIpAddr() {
         return this.ipAddr;
      }

      public String getName() {
         return this.deviceName;
      }
   }

}