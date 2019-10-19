package ARP;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
	static ArrayList<CacheData> cacheTable;
	static ArrayList<ProxyData> proxyTable;

	//자신의 MAC 주소
	byte[] myMacAddr = new byte[ARP_LEN_MAC_VALUE];
	//자신의 IP 주소
	byte[] myIpAddr = new byte[ARP_LEN_IP_VALUE];
	//GARP용 MAC주소
	byte[] myGrtAddr = new byte[ARP_LEN_MAC_VALUE];

	//하드웨어 주소를 변경할 때 변경한다는 것을 확인하는 함수
	boolean changeMac = false;

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

	// 받이온 bytep[]의 ip주소를  내 myIpAddr에 저장하는 함수
	public void setIpAddress(byte[] input) {
		System.arraycopy(input, 0, myIpAddr, 0, ARP_LEN_IP_VALUE);
	}

	//gratuitous일 때 app에서 true값과 주소값을 넣어줌
	public void setGrt(boolean input, byte[] setGrtAddr) {
		changeMac = input;
		System.arraycopy(setGrtAddr, 0, myGrtAddr, 0, ARP_LEN_MAC_VALUE);
	}

	public boolean Send(byte[] input, int length) {

		byte[] dstIpAddr = new byte[ARP_LEN_IP_VALUE];
		byte[] srcIpAddr = new byte[ARP_LEN_IP_VALUE];

		System.arraycopy(this.myIpAddr, 0, srcIpAddr, 0, ARP_LEN_IP_VALUE);

		//gratuious인지 아니면 그냥 basic, proxy인지 확인
		if(changeMac == true) {
			//gratuious
			changeMac = false;

			//dstIp와 srcIp는 같음
			System.arraycopy(this.myIpAddr, 0, dstIpAddr, 0, ARP_LEN_IP_VALUE);

			//send용 ARPHeader세팅
			sendARPHeader(dstIpAddr, srcIpAddr);

			//input 앞에 ARP헤더를 붙여서 byte[]로 나타냄
			//ethernet.send로 보낼 데이터
			byte[] sendData = addHeader(ARP_Header, input);

			//Ethernet.send를 호출하는 부분
			((EthernetLayer)this.GetUnderLayer(0)).Send(sendData, sendData.length);

		}
		else {
			//basic, proxy

			//srcIp는 내가 이미 가지고 있음
			//dstIp는 input의 12byte부터 4바이트
			dstIpAddr = new byte[ARP_LEN_IP_VALUE];

			//arraycopy로 dst ip주소 추출
			System.arraycopy(input, 12, dstIpAddr, 0, ARP_LEN_IP_VALUE);

			//send용 ARPHeader세팅
			sendARPHeader(dstIpAddr, srcIpAddr);

			//input 앞에 ARP헤더를 붙여서 byte[]로 나타냄
			//ethernet.send로 보낼 데이터
			byte[] sendData = addHeader(ARP_Header, input);

			byte[] cacheMac = new byte[ARP_LEN_MAC_VALUE];
			byte[] cacheIp = new byte[ARP_LEN_IP_VALUE];

			System.arraycopy(ARP_Header.mac_recvAddr.addr, 0, cacheMac, 0, ARP_LEN_MAC_VALUE);
			System.arraycopy(ARP_Header.ip_recvAddr.addr, 0, cacheIp, 0, ARP_LEN_IP_VALUE);

			//캐쉬 테이블에 올리는 부분
			addCache(new CacheData(cacheCount,cacheMac, cacheIp, INCOMPLETE));

			//Ethernet.send를 호출하는 부분
			((EthernetLayer)this.GetUnderLayer(0)).Send(sendData, sendData.length);
		}

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
		//gratuitous인지 proxy인지 basic인지 버리는 것인지 결정

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

				//sender의 맥주소 추출
				byte[] sendMacAddr = new byte[ARP_LEN_MAC_VALUE];
				System.arraycopy(input, 8, sendMacAddr, 0, ARP_LEN_MAC_VALUE);

				//추출한 sender의 맥과 아이피 주소를 추가
				changeCache(sendMacAddr, sendIpAddr, COMPLETE);

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
				((EthernetLayer)this.GetUnderLayer(0)).Send(sendData, sendData.length);

			}
		}
		// opcode가 2인 경우
		else {
			//(상대방 쪽에서 보내온 것이 sender이므로 sender의 mac이 중요)
			//sender의 ip와 mac주소 추출
			byte[] senderMac = new byte[ARP_LEN_MAC_VALUE];
			byte[] senderIp = new byte[ARP_LEN_IP_VALUE];

			System.arraycopy(input, 8, senderMac, 0, ARP_LEN_MAC_VALUE);
			System.arraycopy(input, 14, senderIp, 0, ARP_LEN_IP_VALUE);

			//이제 주소를 캐쉬 테이블에 업데이트하는 함수 호출
			//값을 변경 시킴 (mac 주소와 incomplete -> complete)
			changeCache(senderMac, senderIp, COMPLETE);

		}

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
			cacheTimer.schedule(removeCache, 10000);
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
		//		System.out.println("cache비우기 전에 MAC : "+Arrays.toString(myMacAddr));
		cacheTable.clear();
		//		System.out.println("cache비우고 나서 MAC : "+Arrays.toString(myMacAddr));
	}

	//가장 마지막으로 들어온 값 삭제
	public void deleteProxy() {
		proxyTable.remove(proxyTable.size()-1);
	}

//	//Application용 mac주소
//	public byte[] macaddr_byte(_ARP_MAC_ADDR addr) {
//		return addr.addr;
//	}

//	//Application용 IP주소
//	public byte[] ipaddr_byte(_ARP_IP_ADDR addr) {
//		return addr.addr;
//	}
	
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