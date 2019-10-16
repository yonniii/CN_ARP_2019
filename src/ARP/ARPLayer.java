package ARP;

import java.util.ArrayList;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
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
	ArrayList<ProxyData> proxyTable = new ArrayList<>();

	//자신의 MAC 주소
	_ARP_MAC_ADDR myMacAddr = new _ARP_MAC_ADDR();


	//생성자
	public ARPLayer(String pName) {
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

	// 받아온 byte[]의 mac주소를 내 myMacAddr에 저장하는 함수
	public void setMacAddress(byte[] input) {
		System.arraycopy(input, 0, myMacAddr.addr, 0, ARP_LEN_MAC_VALUE);
	}

	public boolean Send(byte[] input, int length) {
		//들어온 input(dstIp, srcIP)를 분리하여 IP주소를 얻어냄 
		//앞의 4바이트는 dst, 뒤의 4바이트는 src
		_ARP_IP_ADDR dstIpAddr = new _ARP_IP_ADDR();
		_ARP_IP_ADDR srcIpAddr = new _ARP_IP_ADDR();

		//arraycopy로 dst랑 src ip주소 추출
		System.arraycopy(input, 0, dstIpAddr.addr, 0, ARP_LEN_IP_VALUE);
		System.arraycopy(input, 4, srcIpAddr.addr, 0, ARP_LEN_IP_VALUE);

		//send용 ARPHeader세팅
		sendARPHeader(dstIpAddr, srcIpAddr);

		//input 앞에 ARP헤더를 붙여서 byte[]로 나타냄
		//ethernet.send로 보낼 데이터
		byte[] sendData = addHeader(ARP_Header, input); 

		//캐쉬 테이블에 올리는 부분
		addCache(new CacheData(ARP_Header.mac_recvAddr, ARP_Header.ip_recvAddr, INCOMPLETE));

		//Ethernet.send를 호출하는 부분
		((EthernetLayer)this.GetUnderLayer()).Send(sendData, sendData.length);

		//보내고 나면 헤더를 새로 초기화
		ResetHeader();

		return true;
	}

	//들어온 ip와 같은 인덱스가 존재할 경우 인덱스의 mac주소를 리턴
	public _ARP_MAC_ADDR isProxy(_ARP_IP_ADDR recv_ip) { //이더넷과 연결

		for(int i=0; i<proxyTable.size();i++) {
			//제대로 인식하는지 확인 필요
			if( proxyTable.get(i).ipAddr == recv_ip) {
				return proxyTable.get(i).macAddr;
			}
		}
		return null;

	}

	public boolean Receive(byte[] input) {
		//opCode가 1인 경우와 opCode가 2인 경우를 구분

		//opCode가 1인 경우
		//(여기까지 올라왔다면 내 mac주소를 삽입한 다음 데이터를 보낸 상대의 주소를 해쉬 테이블에 업데이트, 그 다음 스와핑하여 다시 보냄)
		// 1. 내 맥 주소를  receiver 칸에 삽입
		// 2. sender의 정보를 추출
		// 3. 캐시 테이블 업데이트 (sender의 정보를 업데이트)
		// 4. receive용 헤더 세팅(헤더에서 스와핑 시킴)
		// 5. ARP를 제외한 input의 실제 데이터에 receive용 헤더를 붙임
		// 6. 헤더를 붙인 데이터를 하위 레이어의 send로 전송

		//opCode가 2인 경우
		//(원하는 정보를 얻은 것이므로 원하는 정보를 추출하여 해쉬 테이블을 업데이트 함)
		// 1. sender부분의 mac주소가 우리가 알고 싶었던 주소 -> 추출
		// 2. 주소를 캐시 테이블에 업데이트 

		//먼저 input에서 opCode인 부분을 int 형태로 바꿈
		int opCode = byte2ToInt(input[6], input[7]);

		// 1인지 2인지 확인
		if(opCode == ASK) {
			// 1인 경우
			//proxyARP인지 BASIC인지 확인 해야함 따라서 target의 ip 추출 -> isProxy검사
			//true일 경우 반환되는 데이터 값을 가지고 (그 인덱스에 대한 MAC값)
			//basic arp와 똑같이 진행
			//fasle일 경우
			//basic arp 그대로 진행
			
			//proxy 검색 용 IP주소 추출
			_ARP_IP_ADDR recvIpAddr = new _ARP_IP_ADDR();
			System.arraycopy(input, 24, recvIpAddr, 0, ARP_LEN_IP_VALUE);
			
			//추출한 주소를 가지고 proxy용 recvMac을 구함 (없으면 null)
			_ARP_MAC_ADDR proxyRecvMacAddr = isProxy(recvIpAddr);
			
			if(proxyRecvMacAddr != null) { //Proxy
				//원래 target.mac의 위치에 넣어줌
				System.arraycopy(proxyRecvMacAddr.addr, 0, input, 18, ARP_LEN_MAC_VALUE);
			}
			else { //basic
				//자신의 맥 주소를 추출해서 input의 target.mac부분에 삽입
				_ARP_MAC_ADDR recvMacAddr = new _ARP_MAC_ADDR();
				System.arraycopy(recvMacAddr.addr, 0, input, 18, ARP_LEN_MAC_VALUE);
			}
			
			//sender Mac, Ip
			_ARP_MAC_ADDR senderMac = new _ARP_MAC_ADDR();
			_ARP_IP_ADDR senderIp = new _ARP_IP_ADDR();

			System.arraycopy(input, 8, senderMac.addr, 0, ARP_LEN_MAC_VALUE);
			System.arraycopy(input, 14, senderIp.addr, 0, ARP_LEN_IP_VALUE);

			//sender의 정보는 다 있기 때문에 테이블에 추가
			addCache(new CacheData(senderMac, senderIp, COMPLETE));

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

			//보내고 나면 헤더를 초기화
			ResetHeader();

		}
		else {
			// opcode가 2인 경우
			//(상대방 쪽에서 보내온 것이 sender이므로 sender의 mac이 중요)
			//sender의 ip와 mac주소 추출
			_ARP_MAC_ADDR senderMac = new _ARP_MAC_ADDR();
			_ARP_IP_ADDR senderIp = new _ARP_IP_ADDR();

			System.arraycopy(input, 8, senderMac.addr, 0, ARP_LEN_MAC_VALUE);
			System.arraycopy(input, 14, senderIp.addr, 0, ARP_LEN_IP_VALUE);

			//이제 주소를 캐쉬 테이블에 업데이트하는 함수 호출
			//값을 변경 시킴 (mac 주소와 incomplete -> complete)
			changeCache(new CacheData(senderMac, senderIp, COMPLETE));

		}
		return true;
	}

	//헤더를 추가하는 부분
	public void sendARPHeader(_ARP_IP_ADDR dstIpAddr, _ARP_IP_ADDR srcIpAddr) {
		ARP_Header.opCode = intToByte2(ASK);
		ARP_Header.mac_sendAddr = myMacAddr; //앱에서 mac주소 받음 =>받아오는 함수 (논의해야할 부분)
		ARP_Header.ip_sendAddr= srcIpAddr;
		ARP_Header.ip_recvAddr = dstIpAddr;
		//recv의 mac 주소는 이미 reset에서 0으로 설정   

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
			if(cacheTable.get(i).getIpAddr().equals(givenData.getIpAddr())) {
				check = 1; //이미 있는 경우
				//오류 (어떻게 오류를 표시해야할지 생각)
				return;
			}
		}
		if(check != 1) //테이블에 매개변수의 ip가 없는 경우
			cacheTable.add(givenData);
	}

	//프록시 테이블에 데이터를 추가하는 경우
	public void addProxy(byte[] givenIp, byte[] givenMac, String givenName) {
		//나중에 돌면서 체크 -> 있을 경우 오류로 할지 결정
		_ARP_IP_ADDR ip = new _ARP_IP_ADDR();
		_ARP_MAC_ADDR mac = new _ARP_MAC_ADDR();
		System.arraycopy(givenIp, 0, ip, 0, ARP_LEN_IP_VALUE);
		System.arraycopy(givenIp, 0, mac, 0, ARP_LEN_MAC_VALUE);

		proxyTable.add(new ProxyData(mac, ip, givenName));

	}


	//브로드캐스트로 받은 데이터가 우리 데이터가 아니더라도 ip랑 mac주소는 따오게 됨
	//캐쉬 테이블에 ethernet으로부터 받아온 ip랑 mac 주소를 cache table에 추가
	public void ethernetAddCache(byte[] mac, byte[] ip) {
		_ARP_MAC_ADDR addMac = new _ARP_MAC_ADDR();
		_ARP_IP_ADDR addIp = new _ARP_IP_ADDR();

		System.arraycopy(mac, 0, addMac.addr, 0, mac.length);
		System.arraycopy(ip, 0, addIp.addr, 0, ip.length);

		//cachetable에 추가
		addCache(new CacheData(addMac, addIp, COMPLETE));
	}


	//캐쉬 테이블의 데이터를 complete로 변경
	public void changeCache(CacheData givenData) {
		//Ip addr을 기준으로 찾아서 추가
		int check = 0;
		for(int i = 0; i < cacheTable.size(); i++) {
			if(cacheTable.get(i).getIpAddr().equals(givenData.getIpAddr())) {
				check = 1; //이미 있는 경우

				//값을 변경함
				cacheTable.set(i, givenData);

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

	//Application용 mac주소
	public byte[] macaddr_byte(_ARP_MAC_ADDR addr) {
		return addr.addr;
	}

	//Application용 IP주소
	public byte[] ipaddr_byte(_ARP_IP_ADDR addr) {
		return addr.addr;
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

	class ProxyData {
		private _ARP_MAC_ADDR macAddr;
		private _ARP_IP_ADDR ipAddr;
		private String deviceName;


		public ProxyData(_ARP_MAC_ADDR newMac, _ARP_IP_ADDR newIp, String newName) {
			this.macAddr = newMac;
			this.ipAddr = newIp;
			this.deviceName=newName;
		}

		public void setMacAddr(_ARP_MAC_ADDR givenMac) {
			this.macAddr = givenMac;
		}

		public void setIpAddr(_ARP_IP_ADDR givenIp) {
			this.ipAddr = givenIp;
		}

		public void setDeviceName(String givenName) {
			this.deviceName = givenName;
		}

		public _ARP_MAC_ADDR getMacAddr() {
			return this.macAddr;
		}

		public _ARP_IP_ADDR getIpAddr() {
			return this.ipAddr;
		}

		public String getName() {
			return this.deviceName;
		}
	}

}
