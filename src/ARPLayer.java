package ARP;

import java.util.ArrayList;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	final static int ARP_MAC_TYPE = 2;
	final static int ARP_IP_TYPE = 2;
	final static int OPCODE = 2;
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
	
	public void ARPLayer(String pName) {
		pLayerName = pName;
		ResetHeader();
	}
	
	public void ResetHeader() {
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
		//ip가 들어온 경우
		//길이를 반으로 쪼갬
		//앞의 4바이트는 dst, 뒤의 4바이트는 src
		//이것을 분리하여 헤더를 채움
		//그 다음 나머지 것들도 채움 (op코드나 등등, 채우는 부분은 따로 함수로 뺌)
		//캐쉬 테이블에 올림 (추가, 함수로 뺀다)
		//ethernet.send를 호출함
		return false;
	}
	
	public boolean Receive(byte[] input) {
		//target mac addr을 채움
		//sender의 정보와 Target의 정보를 바꿈
		//op코드 변경
		//캐쉬 테이블 상태 변경 (함수)
		//그다음 하위 레이어로 샌드(send)
		return false;
	}
	
	//헤더를 추가하는 부분
	public void addHeader() {
		
	}
	
	//캐쉬 테이블에 변경
	public void changeCache() {
		
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

