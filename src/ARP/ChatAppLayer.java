package ARP;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;


public class ChatAppLayer implements BaseLayer{
    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    public ChatAppLayer(String pName) {
       pLayerName = pName;
    }


    public boolean Send(byte[] input, int length) {
       byte type_chat = (byte)1;
        if(((TCPLayer)GetUnderLayer(0)).Send(input,type_chat))
            return true;
        return false;
    }
    

    public boolean Receive(byte[] input){
       if(((ApplicationLayer)GetUpperLayer(0)).Receive(input))
            return true;
        return false;
    }
    
    public boolean IPCollision(){
        ((ApplicationLayer) this.GetUpperLayer(0)).IPCollision();
        return true;
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