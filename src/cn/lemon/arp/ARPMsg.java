package cn.lemon.arp;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

public class ARPMsg implements Runnable {
    static JpcapCaptor captor;
    static jpcap.NetworkInterface[] devices;
    static BufferedReader in = new BufferedReader(new InputStreamReader(
            System.in));
    static int i = 0;
    static String str;
    static boolean bl = true;

    public static void main(String[] args) {
        System.out.println(" ..... ARP ....");

        nic();
        try {
            captor = JpcapCaptor.openDevice(devices[i], 65535, false, 2000);  // 创建一个与指定设备的连接并返回该连接
            captor.setFilter("arp", true);                  //过滤得到需要的 ARP 包
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        Runnable runnable = new ARPMsg();
        Thread thread = new Thread(runnable);            //开启一个子线程监听 ARP 报文
        thread.setName("thread1");
        thread.setPriority(6);
        thread.start();

        Scanner s = new Scanner(System.in);         //在 main 线程中 , ，输入 "exit" 用于停止监听
        String input = s.next();
        if (input.equals("exit"))
            System.exit(0); //normal exit


    }


    public void run() {                                     //子线程thread1运行时调用的方法
        while (bl) {
            captor.processPacket(1, handler);                //监听并捕获 ARP 包
        }
    }


    public static int nic() {

        devices = JpcapCaptor.getDeviceList();     // 返回一个网络设备列表

        for (int i = 0; i < devices.length; i++) {            //打印可选设备的网卡信息
            System.out.println(i + ". > " + "NIO_gen_eth: " + devices[i].name);
            for (NetworkInterfaceAddress a : devices[i].addresses) {
                System.out.println("   IP address:" + a.address);
            }
        }

        System.out.print("> Choose the NIC you want to use: ");
        try {
            str = in.readLine();                            //输入数字并选择网卡
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        i = Integer.parseInt(str);
        return i;
    }


    private static PacketReceiver handler = new PacketReceiver() {
        @Override
        public void receivePacket(jpcap.packet.Packet packet) {
            System.out.println("===================================");
            if (Short.valueOf(ARPPacket.ARP_REQUEST).equals(((ARPPacket) packet).operation)) {
                System.out.println("This is arp request message");
            }
            if (Short.valueOf(ARPPacket.ARP_REPLY).equals(((ARPPacket) packet).operation)) {
                System.out.println("This is arp reply message");
            }
            System.out.println("硬件类型       " + ((ARPPacket) packet).hardtype);
            System.out.println("操作类型       " + ((ARPPacket) packet).operation);
            System.out.println("源 MAC 地址 " + ((ARPPacket) packet).getSenderHardwareAddress());
            System.out.println("源 IP 地址   " + ((ARPPacket) packet).getSenderProtocolAddress());
            System.out.println("目标 MAC 地址    " + ((ARPPacket) packet).getTargetHardwareAddress());
            System.out.println("目标 IP 地址     " + ((ARPPacket) packet).getTargetProtocolAddress());
            System.out.println("===================================");
        }
    };


}