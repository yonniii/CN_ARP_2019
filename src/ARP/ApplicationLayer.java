package ARP;

import java.awt.Color;
import java.awt.Container;
import java.awt.EventQueue;
import java.awt.FileDialog;
import java.awt.Font;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.List;
import javax.swing.JList;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;

import javax.sound.sampled.AudioFormat.Encoding;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import ARP.ApplicationLayer.setAddressListener;

public class ApplicationLayer extends JFrame implements BaseLayer {
   public int nUpperLayerCount = 0;
   public String pLayerName = null;
   public BaseLayer p_UnderLayer = null;
   public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
   private static LayerManager m_LayerMgr = new LayerManager();

   JPanel contentPane;
   static List ARP_CacheList;
   JButton ARPCache_ItemDelBtn;
   JButton ARPCache_AllDelBtn;
   JButton ARPCache_IPSendBtn;
   JButton GratARP_SendBtn;
   JButton ProxyARP_AddBtn;
   JButton ProxyARP_DelBtn;
   JTextField ARPCache_IPAddress;
   JTextField GratARP_HWAddress;
   JTextField ProxyARP_Device;
   JTextField ProxyARP_IPAddress;
   JTextField ProxyARP_MacAddress;
   JTextField IP_Address;
   static List ProxyARP_List;

   public static void main(String[] args) {

      m_LayerMgr.AddLayer(new NILayer("NI"));
     // m_LayerMgr.AddLayer(new ChatAppLayer("ChatApp"));
      m_LayerMgr.AddLayer(new IPLayer("IP"));
      m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
      m_LayerMgr.AddLayer(new ARPLayer("ARP"));
      m_LayerMgr.AddLayer(new ApplicationLayer("GUI"));
      m_LayerMgr.AddLayer(new TCPLayer("TCP"));
     // m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *IP ( * TCP ( *ChatApp ( *GUI ) ) ) ) ( *ARP ( *IP ( *TCP ( *GUI ) ) ) ) )");
      m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *ARP ( *IP ( *TCP ( *GUI ) ) ) ) )");
      
      EventQueue.invokeLater(new Runnable() {//GUI구성
         public void run() {
            try {
               ApplicationLayer frame = new ApplicationLayer("APP");
               frame.setVisible(true);
            }
            catch(Exception e) {
               e.printStackTrace();
            }
         }
      });
      
      Renewal_Thread thread = new Renewal_Thread();//테이블 갱신
      Thread object = new Thread(thread);
      object.start();
   }
   
   static ARPLayer arplayer = (ARPLayer)m_LayerMgr.GetLayer("ARP");
   static IPLayer iplayer = (IPLayer)m_LayerMgr.GetLayer("IP");
   static TCPLayer tcplayer = (TCPLayer)m_LayerMgr.GetLayer("TCP");
   static NILayer nilayer = (NILayer)m_LayerMgr.GetLayer("NI");
   private JTextField MAC_Address;

   JComboBox addr_comboBox;
   JButton IP_Setting_Btn = new JButton("Setting");
   
   static class Renewal_Thread implements Runnable{
      public Renewal_Thread() {
         
      }
      
      @Override
      public void run() {
         // TODO Auto-generated method stub
         while(true) {
            try {
               Thread.sleep(500);//0.5초마다 갱신
            }catch(InterruptedException e){
               e.printStackTrace();
            }
            //arplayer의 cache테이블 정보 가져와
            //BASIC ARP

            ARP_CacheList.removeAll();
            for(int i = 0; i < arplayer.cacheTable.size(); i++) {
               String ipaddr = new String(arplayer.ipaddr_byte(arplayer.cacheTable.get(i).getIpAddr()));
               String macaddr = new String(arplayer.macaddr_byte(arplayer.cacheTable.get(i).getMacAddr()));
               int status = arplayer.cacheTable.get(i).getStatus();
               String s;
               if(status == 0) {
                  s = "Incomplete";
               }
               else {
                  s = "Complete";
               }
               ARP_CacheList.addItem(ipaddr+"   "+ macaddr + "  " +  status);//화면에 띄워지는 것인지 고민해봐야함
            }
            //
            
         }
         
         
      }
   }

   public ApplicationLayer(String pName) {

      pLayerName = pName;setTitle(
            "[2\uC870]\uC2EC\uC2B9\uBBFC, \uAC15\uC11C\uC5F0, \uAE40\uC608\uC724, \uC720\uD61C\uACBD, \uC774\uACBD\uC2DD, \uC870\uD604\uC544");
      setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      setBounds(100, 100, 1066, 417);
      contentPane = new JPanel();
      contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
      setContentPane(contentPane);
      contentPane.setLayout(null);

      JPanel ARP_CachePanel = new JPanel();
      ARP_CachePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache",
            TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
      ARP_CachePanel.setBounds(0, 5, 366, 371);
      contentPane.add(ARP_CachePanel);
      ARP_CachePanel.setLayout(null);

      JPanel ARPcacheEditorPanel = new JPanel();
      ARPcacheEditorPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
      ARPcacheEditorPanel.setBounds(10, 15, 340, 254);
      ARP_CachePanel.add(ARPcacheEditorPanel);
      ARPcacheEditorPanel.setLayout(null);

      ARP_CacheList = new List();
      ARP_CacheList.setBounds(0, 0, 340, 254);
      ARPcacheEditorPanel.add(ARP_CacheList);

      ARPCache_ItemDelBtn = new JButton("Item Delete");
      ARPCache_ItemDelBtn.setEnabled(false);
      ARPCache_ItemDelBtn.setBounds(63, 279, 106, 31);
      ARP_CachePanel.add(ARPCache_ItemDelBtn);
      ARPCache_ItemDelBtn.addActionListener(new setAddressListener());

      Label ARPIP_Label = new Label("IP\uC8FC\uC18C");
      ARPIP_Label.setFont(new Font("맑은 고딕", Font.PLAIN, 12));
      ARPIP_Label.setAlignment(Label.CENTER);
      ARPIP_Label.setBounds(7, 332, 69, 23);
      ARP_CachePanel.add(ARPIP_Label);

      ARPCache_AllDelBtn = new JButton("All Delete");
      ARPCache_AllDelBtn.setEnabled(false);
      ARPCache_AllDelBtn.setBounds(195, 279, 106, 31);
      ARP_CachePanel.add(ARPCache_AllDelBtn);
      ARPCache_AllDelBtn.addActionListener(new setAddressListener());

      ARPCache_IPSendBtn = new JButton("Send");
      ARPCache_IPSendBtn.setEnabled(false);
      ARPCache_IPSendBtn.setBounds(282, 332, 68, 26);
      ARP_CachePanel.add(ARPCache_IPSendBtn);

      ARPCache_IPAddress = new JTextField();
      ARPCache_IPAddress.setEnabled(false);
      ARPCache_IPAddress.setColumns(10);
      ARPCache_IPAddress.setBounds(79, 333, 195, 25);
      ARP_CachePanel.add(ARPCache_IPAddress);
      ARPCache_IPSendBtn.addActionListener(new setAddressListener());

      JPanel GratARP_Panel = new JPanel();
      GratARP_Panel.setBorder(
            new TitledBorder(null, "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, null));
      GratARP_Panel.setBounds(742, 10, 307, 155);
      contentPane.add(GratARP_Panel);
      GratARP_Panel.setLayout(null);

      Label HW_Label = new Label("H/W\uC8FC\uC18C");
      HW_Label.setAlignment(Label.CENTER);
      HW_Label.setBounds(10, 20, 69, 23);
      GratARP_Panel.add(HW_Label);
      HW_Label.setFont(new Font("맑은 고딕", Font.PLAIN, 12));

      GratARP_SendBtn = new JButton("\uC804\uC1A1");
      GratARP_SendBtn.setEnabled(false);
      GratARP_SendBtn.setBounds(100, 98, 100, 32);
      GratARP_Panel.add(GratARP_SendBtn);
      GratARP_SendBtn.addActionListener(new setAddressListener());

      GratARP_HWAddress = new JTextField();
      GratARP_HWAddress.setEnabled(false);
      GratARP_HWAddress.setColumns(10);
      GratARP_HWAddress.setBounds(20, 49, 275, 27);
      GratARP_Panel.add(GratARP_HWAddress);

      JPanel ProxyARP_Panel = new JPanel();
      ProxyARP_Panel.setBounds(373, 5, 362, 371);
      contentPane.add(ProxyARP_Panel);
      ProxyARP_Panel.setLayout(null);
      ProxyARP_Panel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Entry",
            TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));

      JPanel ProxyARPeditorPanel = new JPanel();
      ProxyARPeditorPanel.setLayout(null);
      ProxyARPeditorPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
      ProxyARPeditorPanel.setBounds(10, 15, 340, 177);
      ProxyARP_Panel.add(ProxyARPeditorPanel);

      ProxyARP_List = new List();
      ProxyARP_List.setBounds(0, 0, 340, 172);
      ProxyARPeditorPanel.add(ProxyARP_List);

      ProxyARP_AddBtn = new JButton("Add");
      ProxyARP_AddBtn.setEnabled(false);
      ProxyARP_AddBtn.setBounds(23, 319, 140, 31);
      ProxyARP_Panel.add(ProxyARP_AddBtn);
      ProxyARP_AddBtn.addActionListener(new setAddressListener());

      ProxyARP_DelBtn = new JButton("Delete");
      ProxyARP_DelBtn.setEnabled(false);
      ProxyARP_DelBtn.setBounds(195, 319, 140, 31);
      ProxyARP_Panel.add(ProxyARP_DelBtn);

      ProxyARP_Device = new JTextField();
      ProxyARP_Device.setEnabled(false);
      ProxyARP_Device.setBounds(144, 215, 158, 21);
      ProxyARP_Panel.add(ProxyARP_Device);
      ProxyARP_Device.setColumns(10);

      ProxyARP_IPAddress = new JTextField();
      ProxyARP_IPAddress.setEnabled(false);
      ProxyARP_IPAddress.setBounds(144, 246, 158, 21);
      ProxyARP_Panel.add(ProxyARP_IPAddress);
      ProxyARP_IPAddress.setColumns(10);

      ProxyARP_MacAddress = new JTextField();
      ProxyARP_MacAddress.setEnabled(false);
      ProxyARP_MacAddress.setBounds(144, 277, 158, 21);
      ProxyARP_Panel.add(ProxyARP_MacAddress);
      ProxyARP_MacAddress.setColumns(10);

      JLabel Device_Label = new JLabel("Device");
      Device_Label.setBounds(61, 218, 57, 15);
      ProxyARP_Panel.add(Device_Label);

      JLabel ProxyARPIP_Label = new JLabel("IP_\uC8FC\uC18C");
      ProxyARPIP_Label.setBounds(61, 249, 57, 15);
      ProxyARP_Panel.add(ProxyARPIP_Label);

      JLabel ProxyARPMac_Label = new JLabel("MAC_\uC8FC\uC18C");
      ProxyARPMac_Label.setBounds(61, 280, 70, 15);
      ProxyARP_Panel.add(ProxyARPMac_Label);
      ProxyARP_DelBtn.addActionListener(new setAddressListener());

      JPanel Address_Panel = new JPanel();
      Address_Panel.setLayout(null);
      Address_Panel.setBorder(new TitledBorder(null, "Address", TitledBorder.LEADING, TitledBorder.TOP, null, null));
      Address_Panel.setBounds(735, 175, 312, 201);
      contentPane.add(Address_Panel);

      Label Mac_Label = new Label("MAC");
      Mac_Label.setAlignment(Label.CENTER);
      Mac_Label.setFont(new Font("맑은 고딕", Font.PLAIN, 10));
      Mac_Label.setBounds(4, 68, 37, 21);
      Address_Panel.add(Mac_Label);

      Label IP_Label = new Label("IP");
      IP_Label.setAlignment(Label.CENTER);
      IP_Label.setFont(new Font("맑은 고딕", Font.PLAIN, 10));
      IP_Label.setBounds(3, 114, 39, 23);
      Address_Panel.add(IP_Label);

      IP_Address = new JTextField();
      IP_Address.setBounds(56, 114, 246, 21);
      Address_Panel.add(IP_Address);
      IP_Address.setColumns(10);
      
      MAC_Address = new JTextField();
      MAC_Address.setColumns(10);
      MAC_Address.setBounds(56, 68, 246, 21);
      Address_Panel.add(MAC_Address);
      
      String[] nic = new String[((NILayer) m_LayerMgr.GetLayer("Ni")).m_pAdapterList.size()];
         for (int i = 0; i < ((NILayer) m_LayerMgr.GetLayer("Ni")).m_pAdapterList.size(); i++) {
            nic[i] = ((NILayer) m_LayerMgr.GetLayer("Ni")).m_pAdapterList.get(i).getDescription()
                  + ((NILayer) m_LayerMgr.GetLayer("Ni")).m_pAdapterList.get(i).getName();
         }
       addr_comboBox = new JComboBox(nic);
      addr_comboBox.setBounds(56, 28, 246, 23);
      Address_Panel.add(addr_comboBox);
      
      JButton IP_Setting_Btn = new JButton("Setting");
      IP_Setting_Btn.setBounds(211, 155, 91, 23);
      Address_Panel.add(IP_Setting_Btn);
   }

   class setAddressListener implements ActionListener {
      @Override
      public void actionPerformed(ActionEvent e) {
         if (e.getSource() == addr_comboBox) {
               byte[] mac = new byte[0];
               try {
                  mac = nilayer.m_pAdapterList.get(addr_comboBox.getSelectedIndex()).getHardwareAddress();
               } catch (IOException e1) {
                  e1.printStackTrace();
               }
               String macAddr = new String(mac);
               MAC_Address.setText(macAddr);
            }
         
         //send버튼 누르면 ip주소 mac주소 incomplete띄우기, arplayer에서 얻어오기(thread확인)
         
         if(e.getSource() == ARPCache_IPSendBtn) {
            iplayer.Send(ARPCache_IPAddress.getText());
            byte[] no = null;
            tcplayer.Send(no);
            arplayer.setMacAddress(MAC_Address.getText().getBytes());
            for(int i = 0; i < arplayer.cacheTable.size(); i++) {
            	if(arplayer.ipaddr_byte(arplayer.cacheTable.get(i).getIpAddr()) == ARPCache_IPAddress.getText().getBytes()) {
            		if(arplayer.cacheTable.get(i).getStatus() == 1) {
            			JOptionPane.showMessageDialog(null, "이미 MAC 주소가 존재합니다.", "ERROR", JOptionPane.ERROR_MESSAGE);
            			ARPCache_IPAddress.setText("");
            		}
            	}
            }
         }
         if(e.getSource() == IP_Setting_Btn) {
        	 arplayer.setIpAddress(IP_Address.getText().getBytes());
         }
         if(e.getSource() == ARPCache_ItemDelBtn) {
         //아이템 삭제
        	 arplayer.deleteCache();
         }
         if(e.getSource() == ARPCache_AllDelBtn) {
         //캐시테이블 전체 삭제
        	 arplayer.deleteAllCache();
         }
         if(e.getSource() == ProxyARP_AddBtn) {
            String device = ProxyARP_Device.getText();
            byte[] ip = ProxyARP_IPAddress.getText().getBytes();
            byte[] mac = ProxyARP_MacAddress.getText().getBytes();
            arplayer.addProxy(ip, mac, device);
            ProxyARP_List.addItem(device+"  "+ip+"  "+mac);
            
         }
         if(e.getSource() == ProxyARP_DelBtn) {
            //테이블삭제(ARP에서)
        	 arplayer.deleteProxy();
         }
         if(e.getSource() == GratARP_SendBtn) {
            //change_mac(ARP에서 한 것 불러와야함) 
         }
         
         
            
         //iplayer로 보낼때 ip만 보내면 된다.(string로)
         //add버튼 누르면 proxy arp entry에 device ip주소 ethernet주소 띄우기(thread확인)
         //iplayer로 보냄(string로)
         //delete는 다 삭제하게 

      }
   }
//   public boolean Receive(byte[] input) {
//      //대답이 오면 ip complete로 덮어씌움 arplayer에서 얻어오기(thread 확인)
//      return true;
//   }
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
   public String GetLayerName() {
      // TODO Auto-generated method stub
      return pLayerName;
   }

   @Override
   public BaseLayer GetUnderLayer() {
      // TODO Auto-generated method stub
      if (p_UnderLayer == null)
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
   public void SetUpperUnderLayer(BaseLayer pUULayer) {
      this.SetUpperLayer(pUULayer);
      pUULayer.SetUnderLayer(this);

   }
}