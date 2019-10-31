
package ARP;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.List;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileSystemView;

import org.jnetpcap.PcapIf;


public class ApplicationLayer extends JFrame implements BaseLayer {
   public int nUpperLayerCount = 0;
   public int nUnderLayerCount = 0;
   public String pLayerName = null;
   public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
   public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
   private static LayerManager m_LayerMgr = new LayerManager();

   String folderPath = "";
   private JTextField MAC_Address;
   static JComboBox<PcapIf> addr_comboBox;
   JButton IP_Setting_Btn;
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
   ARPLayer arplayer = (ARPLayer)m_LayerMgr.GetLayer("ARP");
   IPLayer iplayer = (IPLayer)m_LayerMgr.GetLayer("IP");
   TCPLayer tcplayer = (TCPLayer)m_LayerMgr.GetLayer("TCP");
   NILayer nilayer = (NILayer)m_LayerMgr.GetLayer("NI");
   EthernetLayer ethernetlayer = (EthernetLayer)m_LayerMgr.GetLayer("Ethernet");
   FileAppLayer fileapplayer = (FileAppLayer)m_LayerMgr.GetLayer("FileApp");
   ChatAppLayer chatapplayer = (ChatAppLayer)m_LayerMgr.GetLayer("ChatApp");
   private JTextField Chatting_Text;
   private JPanel File_Panel;
   private JPanel panel_4;
   private JTextArea File_Area;
   private JPanel panel_5;
   private JProgressBar ProgressBar;
   private JButton File_Btn;
   private JButton File_Transfer_Btn;
   JButton Chatting_Send_Btn;
   private static List Chatting_Area;
   private JPanel chatfile_Panel;
   private Label chatfile_MacLabel;
   private Label label_1;
   private JTextField chatfile_IPsrc;
   private JTextField chatfile_MacAddr;
   private JComboBox chatfile_comboBox;
   private JButton chatfile_Setting;
   private JTextField chatfile_IPdst;
   public static void main(String[] args) {

      m_LayerMgr.AddLayer(new NILayer("NI"));
      m_LayerMgr.AddLayer(new IPLayer("IP"));
      m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
      m_LayerMgr.AddLayer(new ARPLayer("ARP"));
      m_LayerMgr.AddLayer(new ApplicationLayer("GUI"));
      m_LayerMgr.AddLayer(new TCPLayer("TCP"));
      m_LayerMgr.AddLayer(new FileAppLayer("FileApp"));
      m_LayerMgr.AddLayer(new ChatAppLayer("ChatApp"));
      m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *ARP ( *IP ( *TCP ( *ChatApp ( *GUI ) *FileApp ( *GUI ) ) ) ) *IP ( *TCP ( *ChatApp ( *GUI ) *FileApp ( *GUI ) ) ) ) )");

      EventQueue.invokeLater(new Runnable() {
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

      Renewal_Thread thread = new Renewal_Thread(((ARPLayer)m_LayerMgr.GetLayer("ARP")));
      Thread object = new Thread(thread);
      object.start();
   }

   static class Renewal_Thread implements Runnable{
      ARPLayer arp;

      public Renewal_Thread(ARPLayer givenArp) {
         this.arp = givenArp;
      }

      @Override
      public void run() {
         // TODO Auto-generated method stub
         while(true) {
            try {
               Thread.sleep(50);
            }catch(InterruptedException e){
               e.printStackTrace();
            }
            //BASIC ARP
            ARPLayer temp = arp;

            ARP_CacheList.removeAll();
            for(int i = 0; i <((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.size(); i++) {
               String macaddr = "";
               for (int j = 0; j < ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getMacAddr().length; j++)
                  macaddr += String.format("%02X%s",((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getMacAddr()[j], (j < ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getMacAddr().length - 1) ? "-" : "");
               String ipaddr = "";
               for (int j = 0; j < ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getIpAddr().length; j++) {
                  int senderip = ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getIpAddr()[j] & 0xff;
                  ipaddr += String.format("%d%s", senderip, (j < ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getIpAddr().length - 1) ? "." : "");
               }
               int status = ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getStatus();
               String s ="";
               if(status == 0) {
                  s = "Incomplete";
               }
               else if(status ==1){
                  s = "Complete";
               }
               else if(status ==2) {
                  s = "Invalid";
               }

               ARP_CacheList.addItem(ipaddr +"   "+ macaddr + "  " +  s);
            }
         }
      }
   }

   public ApplicationLayer(String pName) {

      pLayerName = pName;setTitle(
            "[2\uC870]\uC2EC\uC2B9\uBBFC, \uAC15\uC11C\uC5F0, \uAE40\uC608\uC724, \uC720\uD61C\uACBD, \uC774\uACBD\uC2DD, \uC870\uD604\uC544");
      setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      setBounds(100, 100, 1100, 692);
      contentPane = new JPanel();
      contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
      setContentPane(contentPane);
      contentPane.setLayout(null);

      JPanel ARP_CachePanel = new JPanel();
      ARP_CachePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache",
            TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
      ARP_CachePanel.setBounds(0, 5, 390, 371);
      contentPane.add(ARP_CachePanel);
      ARP_CachePanel.setLayout(null);

      JPanel ARPcacheEditorPanel = new JPanel();
      ARPcacheEditorPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
      ARPcacheEditorPanel.setBounds(10, 15, 368, 254);
      ARP_CachePanel.add(ARPcacheEditorPanel);
      ARPcacheEditorPanel.setLayout(null);

      ARP_CacheList = new List();
      ARP_CacheList.setBounds(0, 0, 368, 254);
      ARPcacheEditorPanel.add(ARP_CacheList);

      ARPCache_ItemDelBtn = new JButton("Item Delete");
      ARPCache_ItemDelBtn.setBounds(81, 279, 106, 31);
      ARP_CachePanel.add(ARPCache_ItemDelBtn);
      ARPCache_ItemDelBtn.addActionListener(new setAddressListener());

      Label ARPIP_Label = new Label("IP\uC8FC\uC18C");
      ARPIP_Label.setFont(new Font("맑은 고딕", Font.PLAIN, 12));
      ARPIP_Label.setAlignment(Label.CENTER);
      ARPIP_Label.setBounds(7, 332, 69, 23);
      ARP_CachePanel.add(ARPIP_Label);

      ARPCache_AllDelBtn = new JButton("All Delete");
      ARPCache_AllDelBtn.setBounds(213, 279, 106, 31);
      ARP_CachePanel.add(ARPCache_AllDelBtn);
      ARPCache_AllDelBtn.addActionListener(new setAddressListener());

      ARPCache_IPSendBtn = new JButton("Send");
      ARPCache_IPSendBtn.setBounds(282, 332, 68, 26);
      ARP_CachePanel.add(ARPCache_IPSendBtn);

      ARPCache_IPAddress = new JTextField();
      ARPCache_IPAddress.setColumns(10);
      ARPCache_IPAddress.setBounds(79, 333, 195, 25);
      ARP_CachePanel.add(ARPCache_IPAddress);
      ARPCache_IPSendBtn.addActionListener(new setAddressListener());

      JPanel GratARP_Panel = new JPanel();
      GratARP_Panel.setBorder(
            new TitledBorder(null, "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, null));
      GratARP_Panel.setBounds(767, 10, 307, 155);
      contentPane.add(GratARP_Panel);
      GratARP_Panel.setLayout(null);

      Label HW_Label = new Label("H/W\uC8FC\uC18C");
      HW_Label.setAlignment(Label.CENTER);
      HW_Label.setBounds(10, 20, 69, 23);
      GratARP_Panel.add(HW_Label);
      HW_Label.setFont(new Font("맑은 고딕", Font.PLAIN, 12));

      GratARP_SendBtn = new JButton("\uC804\uC1A1");
      GratARP_SendBtn.setBounds(100, 98, 100, 32);
      GratARP_Panel.add(GratARP_SendBtn);
      GratARP_SendBtn.addActionListener(new setAddressListener());

      GratARP_HWAddress = new JTextField();
      GratARP_HWAddress.setColumns(10);
      GratARP_HWAddress.setBounds(20, 49, 275, 27);
      GratARP_Panel.add(GratARP_HWAddress);

      JPanel ProxyARP_Panel = new JPanel();
      ProxyARP_Panel.setBounds(393, 5, 362, 371);
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
      ProxyARP_AddBtn.setBounds(23, 319, 140, 31);
      ProxyARP_Panel.add(ProxyARP_AddBtn);
      ProxyARP_AddBtn.addActionListener(new setAddressListener());

      ProxyARP_DelBtn = new JButton("Delete");
      ProxyARP_DelBtn.setBounds(195, 319, 140, 31);
      ProxyARP_Panel.add(ProxyARP_DelBtn);

      ProxyARP_Device = new JTextField();
      ProxyARP_Device.setBounds(144, 215, 158, 21);
      ProxyARP_Panel.add(ProxyARP_Device);
      ProxyARP_Device.setColumns(10);

      ProxyARP_IPAddress = new JTextField();
      ProxyARP_IPAddress.setBounds(144, 246, 158, 21);
      ProxyARP_Panel.add(ProxyARP_IPAddress);
      ProxyARP_IPAddress.setColumns(10);

      ProxyARP_MacAddress = new JTextField();
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
      Address_Panel.setBounds(762, 175, 312, 201);
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

      String[] nic = new String[((NILayer)m_LayerMgr.GetLayer("NI")).m_pAdapterList.size()];
      for (int i = 0; i < ((NILayer)m_LayerMgr.GetLayer("NI")).m_pAdapterList.size(); i++) {
         nic[i] = ((NILayer)m_LayerMgr.GetLayer("NI")).m_pAdapterList.get(i).getDescription()
               + ((NILayer)m_LayerMgr.GetLayer("NI")).m_pAdapterList.get(i).getName();
      }
      addr_comboBox = new JComboBox(nic);
      addr_comboBox.setBounds(56, 28, 246, 23);
      Address_Panel.add(addr_comboBox);
      addr_comboBox.addActionListener(new setAddressListener());

      IP_Setting_Btn = new JButton("Setting");
      IP_Setting_Btn.setBounds(211, 155, 91, 23);
      IP_Setting_Btn.addActionListener(new setAddressListener());
      Address_Panel.add(IP_Setting_Btn);

      JPanel Chatting_Panel = new JPanel();
      Chatting_Panel.setLayout(null);
      Chatting_Panel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "chatting",

            TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
      Chatting_Panel.setBounds(0, 378, 390, 276);
      contentPane.add(Chatting_Panel);

      Chatting_Send_Btn = new JButton("Send");
      Chatting_Send_Btn.addActionListener(new setAddressListener());
      Chatting_Send_Btn.setBounds(308, 229, 80, 36);
      Chatting_Panel.add(Chatting_Send_Btn);

      Chatting_Area = new List();
      Chatting_Area.setBounds(10, 15, 368, 210);
      Chatting_Panel.add(Chatting_Area);

      JPanel panel_1 = new JPanel();
      panel_1.setLayout(null);
      panel_1.setBounds(10, 15, 368, 210);
      Chatting_Panel.add(panel_1);

      Chatting_Text = new JTextField();
      Chatting_Text.setBounds(10, 230, 286, 36);
      Chatting_Panel.add(Chatting_Text);
      Chatting_Text.setColumns(10);

      JPanel panel_2 = new JPanel();
      panel_2.setLayout(null);
      panel_2.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
      panel_2.setBounds(10, 230, 285, 36);
      Chatting_Panel.add(panel_2);

      File_Panel = new JPanel();
      File_Panel.setLayout(null);
      File_Panel.setBorder(new TitledBorder(UIManager.getBorder("TiltleBorder.border"), "file transfer",

            TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
      File_Panel.setBounds(390, 378, 362, 276);
      contentPane.add(File_Panel);

      panel_4 = new JPanel();
      panel_4.setLayout(null);
      panel_4.setBounds(10, 282, 356, 30);
      File_Panel.add(panel_4);

      File_Area = new JTextArea();
      File_Area.setEditable(false);
      File_Area.setBounds(8, 36, 342, 37);
      File_Panel.add(File_Area);

      panel_5 = new JPanel();
      panel_5.setLayout(null);
      panel_5.setBounds(10, 284, 356, 30);
      File_Panel.add(panel_5);

      ProgressBar = new JProgressBar(0, 100);
      ProgressBar.setBounds(10, 141, 340, 37);
      File_Panel.add(ProgressBar);
      ProgressBar.setMaximum(100);

      File_Btn = new JButton("File");
      File_Btn.setBounds(215, 93, 135, 30);
      File_Panel.add(File_Btn);
      File_Btn.addActionListener(new setAddressListener());

      File_Transfer_Btn = new JButton("Transfer");
      File_Transfer_Btn.setBounds(215, 196, 135, 30);
      File_Panel.add(File_Transfer_Btn);
      File_Transfer_Btn.addActionListener(new setAddressListener());

      chatfile_Panel = new JPanel();
      chatfile_Panel.setLayout(null);
      chatfile_Panel.setBorder(new TitledBorder(null, "Address", TitledBorder.LEADING, TitledBorder.TOP, null, null));
      chatfile_Panel.setBounds(762, 378, 312, 276);
      contentPane.add(chatfile_Panel);

      chatfile_MacLabel = new Label("MAC Src  ");
      chatfile_MacLabel.setFont(new Font("맑은 고딕", Font.PLAIN, 10));
      chatfile_MacLabel.setAlignment(Label.CENTER);
      chatfile_MacLabel.setBounds(10, 72, 60, 21);
      chatfile_Panel.add(chatfile_MacLabel);

      label_1 = new Label("IP Src ");
      label_1.setFont(new Font("맑은 고딕", Font.PLAIN, 10));
      label_1.setAlignment(Label.CENTER);
      label_1.setBounds(23, 126, 47, 23);
      chatfile_Panel.add(label_1);

      chatfile_IPsrc = new JTextField();
      chatfile_IPsrc.setColumns(10);
      chatfile_IPsrc.setBounds(57, 155, 246, 21);
      chatfile_Panel.add(chatfile_IPsrc);

      chatfile_MacAddr = new JTextField();
      chatfile_MacAddr.setColumns(10);
      chatfile_MacAddr.setBounds(57, 99, 246, 21);
      chatfile_Panel.add(chatfile_MacAddr);

      chatfile_comboBox = new JComboBox(nic);
      chatfile_comboBox.setBounds(57, 33, 246, 23);
      chatfile_Panel.add(chatfile_comboBox);
      chatfile_comboBox.addActionListener(new setAddressListener());

      chatfile_Setting = new JButton("Setting");
      chatfile_Setting.setBounds(212, 240, 91, 23);
      chatfile_Panel.add(chatfile_Setting);
      chatfile_Setting.addActionListener(new setAddressListener());

      chatfile_IPdst = new JTextField();
      chatfile_IPdst.setColumns(10);
      chatfile_IPdst.setBounds(57, 209, 246, 21);
      chatfile_Panel.add(chatfile_IPdst);

      Label label_2 = new Label("IP Dst ");
      label_2.setFont(new Font("맑은 고딕", Font.PLAIN, 10));
      label_2.setAlignment(Label.CENTER);
      label_2.setBounds(31, 182, 39, 23);
      chatfile_Panel.add(label_2);
   }



   class setAddressListener implements ActionListener {

      byte[] macAddr2byte(String addr){
         byte[] buf = new byte[6];
         buf[0] = (byte) Integer.parseInt(addr.substring(0,2),16);
         buf[1] = (byte) Integer.parseInt(addr.substring(2,4),16);
         buf[2] = (byte) Integer.parseInt(addr.substring(4,6),16);
         buf[3] = (byte) Integer.parseInt(addr.substring(6,8),16);
         buf[4] = (byte) Integer.parseInt(addr.substring(8,10),16);
         buf[5] = (byte) Integer.parseInt(addr.substring(10,12),16);
         return buf;
      }



      @Override
      public void actionPerformed(ActionEvent e) {
         if (e.getSource() == addr_comboBox) {
            byte[] mac = new byte[0];
            try {

               mac = nilayer.m_pAdapterList.get(addr_comboBox.getSelectedIndex()).getHardwareAddress();
               nilayer.SetAdapterNumber(addr_comboBox.getSelectedIndex());
            } catch (IOException e1) {
               e1.printStackTrace();
            }

            String macAddr = "";
            for (int i = 0; i < mac.length; i++)
               macAddr += String.format("%02X%s", mac[i], (i < mac.length - 1) ? "" : "");
            MAC_Address.setText(macAddr);
         }


         if(e.getSource() == ARPCache_IPSendBtn) {

            new Thread( ()->{
               String[] IP_dst = ARPCache_IPAddress.getText().split("\\.");
               byte[] str2int_dst = new byte[4];
               for (int i = 0; i < 4; i++) {
                  str2int_dst[i] = (byte) Integer.parseInt(IP_dst[i]);
                  //System.out.println(str2int[i]);
               }
               iplayer.setDstIPAddress(str2int_dst);
               byte[] no = null;


               for (int i = 0; i < ((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.size(); i++) {
                  String[] ARPIP_addr = ARPCache_IPAddress.getText().split("\\.");
                  byte[] str2int = new byte[4];
                  for (int j = 0; j < 4; j++) {
                     str2int[j] = (byte) Integer.parseInt(ARPIP_addr[j]);
                  }
                  if (Arrays.equals(((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getIpAddr(), str2int)) {
                     
                     if (((ARPLayer)m_LayerMgr.GetLayer("ARP")).cacheTable.get(i).getStatus() == 1) {
                      
                        JOptionPane.showMessageDialog(null, "이미 MAC주소가 존재합니다.", "ERROR", JOptionPane.ERROR_MESSAGE);
                     }
                  }
               }

               tcplayer.Send(no);
               ARPCache_IPAddress.setText("");
            }).start();
         }
         if(e.getSource() == IP_Setting_Btn) {
            String[] IP_addr = IP_Address.getText().split("\\.");
            byte[] str2int = new byte[4];
            for (int i = 0; i < 4; i++) {
               str2int[i] = (byte) Integer.parseInt(IP_addr[i]);
            }
            byte[] macAddr_byte = macAddr2byte(MAC_Address.getText());
            arplayer.setMacAddress(macAddr_byte);
            ethernetlayer.setHeaderMac(macAddr_byte);
            iplayer.setSrcIPAddress(str2int);
            arplayer.setIpAddress(str2int);
         }
         if(e.getSource() == ARPCache_ItemDelBtn) {
            arplayer.deleteCache();
         }
         if(e.getSource() == ARPCache_AllDelBtn) {
            arplayer.deleteAllCache();
         }
         if(e.getSource() == ProxyARP_AddBtn) {
            String device = ProxyARP_Device.getText();
            String ip = ProxyARP_IPAddress.getText();
            String mac = ProxyARP_MacAddress.getText();
            String[] Proxy_IP_addr = ProxyARP_IPAddress.getText().split("\\.");
            byte[] str2int = new byte[4];
            for (int j = 0; j < 4; j++) {
               str2int[j] = (byte) Integer.parseInt(Proxy_IP_addr[j]);
            }
            arplayer.addProxy(str2int, macAddr2byte(mac), device);
            ProxyARP_List.addItem("Interface0  "+ip+"  "+mac);

         }
         if(e.getSource() == ProxyARP_DelBtn) {
            arplayer.deleteProxy();
            ProxyARP_List.removeAll();
         }
         if(e.getSource() == GratARP_SendBtn) {
            byte[] no = null;
            arplayer.setGrt(true, macAddr2byte(GratARP_HWAddress.getText()));
            tcplayer.Send(no);
            GratARP_HWAddress.setText("");
         }

         if(e.getSource() == chatfile_comboBox) {
            byte[] mac = new byte[0];
            try {

               mac = nilayer.m_pAdapterList.get(chatfile_comboBox.getSelectedIndex()).getHardwareAddress();
               nilayer.SetAdapterNumber(chatfile_comboBox.getSelectedIndex());
            } catch (IOException e1) {
               e1.printStackTrace();
            }

            String macAddr = "";
            for (int i = 0; i < mac.length; i++)
               macAddr += String.format("%02X%s", mac[i], (i < mac.length - 1) ? "" : "");
            chatfile_MacAddr.setText(macAddr);
         }
         if(e.getSource() == chatfile_Setting) {
            String[] IP_src = chatfile_IPsrc.getText().split("\\.");
            String[] IP_dst = chatfile_IPdst.getText().split("\\.");
            byte[] str2int_src = new byte[4];
            byte[] str2int_dst = new byte[4];
            for (int i = 0; i < 4; i++) {
               str2int_src[i] = (byte) Integer.parseInt(IP_src[i]);
               str2int_dst[i] = (byte)Integer.parseInt(IP_dst[i]);
            }
            iplayer.setSrcIPAddress(str2int_src);
            iplayer.setDstIPAddress(str2int_dst);
         }
         if(e.getSource() == Chatting_Send_Btn){
            Chatting_Area.addItem("[SEND]:" + Chatting_Text.getText() + "\n");
            byte[] n =  Chatting_Text.getText().getBytes();
            //                Receive(n);
            chatapplayer.Send(Chatting_Text.getText().getBytes(), Chatting_Text.getText().getBytes().length);
         }
         if(e.getSource() == File_Btn){
            JFileChooser chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory()); 
            chooser.setAcceptAllFileFilterUsed(true); 
            chooser.setDialogTitle("file select"); 

            int returnVal = chooser.showOpenDialog(null);

            if(returnVal == JFileChooser.APPROVE_OPTION) { 
               folderPath = chooser.getSelectedFile().toString();
               File_Area.append(folderPath);
               File_Area.setText(folderPath);
            }else if(returnVal == JFileChooser.CANCEL_OPTION){ 
               System.out.println("cancel");
               folderPath = "";
            }
         }
         if(e.getSource() == File_Transfer_Btn){
            File file = new File(folderPath);
            Chatting_Area.addItem("[SEND]:"+file.getName()+"\n");
            File_Area.setText("");
            fileapplayer.Send(folderPath);

         }
      }
   }
   public int count=0;

   public boolean Receive(byte[] input) {
 
      String in = new String(input).trim();
      System.out.println(in);
      count++;
      Receive2(in, count);


      return true;
   }
   
   public void Receive2(String input, int c) {//1
      if(c==2) {
         Chatting_Area.addItem("[RECV]:" + input + "\n");
         count=0;
      }
   }

   public void IPCollision()
   {
      JOptionPane.showMessageDialog(null, "IP COLLISION", "ERROR", JOptionPane.ERROR_MESSAGE);
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