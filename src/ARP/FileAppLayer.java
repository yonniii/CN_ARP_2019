package ARP;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;


public class FileAppLayer implements BaseLayer {

    public int nUpperLayerCount = 0;
    public int nUnderLayerCount = 0;
    public String pLayerName = null;
    public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    byte[] b;
    String file_path = null;
    String Receive_name = null;


    public FileAppLayer(String pName) {
        // TODO Auto-generated constructor stub
        pLayerName = pName;

    }
    byte[] intToByte2(int value) { 
        byte[] byteArray = new byte[2];
        byteArray[1] = (byte)(value >> 8);
        byteArray[0] = (byte)(value);
        return byteArray;
    }

    public boolean Send( String filepath) {
        BufferedInputStream bs = null;
        String[] pathname = filepath.split("\\\\");
        String file_name = pathname[pathname.length - 1].trim();
        byte [] file_byteName = file_name.getBytes();
        byte[] file_length = intToByte2(file_name.length()); 
        try {
            bs = new BufferedInputStream(new FileInputStream(filepath.trim()));
            b = new byte[bs.available()]; //
            while (bs.read(b) != -1) {
            }
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            try {
                bs.close(); //
            } catch (Exception e) {
                System.out.println(e);
            }
        }
        byte[] input = ObjToByte(file_byteName,file_length,b);

        byte type_file = (byte)2;
        if(((TCPLayer)GetUnderLayer(0)).Send(input,type_file)) {
            return true;
        }
        return false;

    }
    public byte[] ObjToByte(byte[]filename, byte[] nameLength, byte[] input) { //
        int headersize = filename.length + nameLength.length;
        byte[] buf = new byte[headersize+input.length];
        buf[0] = nameLength[0];
        buf[1] = nameLength[1];

        for(int i =0; i<filename.length; i++) {
            buf[i+2] = filename[i];
        }

        for (int i = 0; i < input.length; i++)
            buf[headersize + i] = input[i];//

        return buf; //
    }
    public byte[] RemoveCappHeader(byte[] input) {
        int nameLength = byte2ToInt(input[0], input[1]);
        int dataIndex = nameLength + 2;
        byte [] name = new byte[nameLength];
        int input_len = input.length;

        for(int i =0; i<nameLength; i++) {
            name[i] = input[2+i];
        }
        Receive_name = new String(name).trim();
        byte[] by = new byte[input_len-(2+nameLength)];
        for(int k =0; k<by.length; k++) {
            by[k] = input[dataIndex + k];
        }
        return by;
    }
    int byte2ToInt(byte one0, byte two1) {
        int number = (one0 & 0xFF) | ((two1 & 0xFF ) << 8);
        return number;
    }
    public synchronized boolean Receive(byte[] input) {
        System.out.println("FileApp_Receive");
        BufferedOutputStream bs = null;
        byte[] data = RemoveCappHeader(input);
        try {
            bs = new BufferedOutputStream(new FileOutputStream(Receive_name.trim()));
        } catch (Exception e) {
            System.out.println(e);
        }
        try {
            bs.write(data);
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            try {
                bs.close();
            } catch (Exception e) {
                System.out.println(e);
            }
        }
        ((ApplicationLayer)this.GetUpperLayer(0)).Receive("File Receive\n".getBytes());
        return true;
    }


    byte[] intToByte4(int value) { 
        byte[] byteArray = new byte[4];
        byteArray[0] = (byte) (value >> 24);
        byteArray[1] = (byte) (value >> 16);
        byteArray[2] = (byte) (value >> 8);
        byteArray[3] = (byte) (value);
        return byteArray;
    }

    public static int byte4Int(byte one, byte two, byte three, byte four) {
        int s1 = one & 0xFF;
        int s2 = two & 0xFF;
        int s3 = three & 0xFF;
        int s4 = four & 0xFF;

        return ((s1 << 24) + (s2 << 16) + (s3 << 8) + (s4 << 0));
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