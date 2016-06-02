package cn.lemon.arp;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Date;

public class ARPCaptor {

    private static NetworkInterface[] devices;    //所有网卡设备
    private static final String fileName = ".\\ARP_info.txt";    //日志文件地址

    public static void main(String[] args) throws Exception {
        ARPCaptor arpCaptor = new ARPCaptor();
        arpCaptor.start();
    }


    public void start() {

        File file = new File(fileName);
        if (file.exists()) {
            file.delete();
        }

        writeFile("代码运行开始时间：" + new Date());

        showNetworkAdapterInfo();   //打印网卡信息

        for (int i = 0; i < devices.length; i++) {

            try {
                JpcapCaptor jpcapCaptor = openDevice(devices[i]);  //打开网卡
                printARPPacketInfo(jpcapCaptor, i + 1);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    public void printARPPacketInfo(JpcapCaptor captor, int position) {

        writeFile("========================第 " + position + " 网卡 ARP 数据包解析 ========================");
        System.out.println();

        long start = System.currentTimeMillis();
        for (int i = 0; i < 5; i++) { // 包的数量为 5
            ARPPacket arp = arpCap(captor);   //抓包
            if (arp == null) {
                return;
            }
            EthernetPacket ethernetPacket = (EthernetPacket) arp.datalink;

            writeFile("-------------- 包 " + (i + 1) + "--------------");
            System.out.println();

            // EthernetPacket   以太网数据包
            String sourceAddress = ethernetPacket.getSourceAddress();   //源mac地址
            String destinationAddress = ethernetPacket.getDestinationAddress();  //目的mac地址

            writeFile("帧类型: " + ethernetPacket.frametype);
            // arp 内容解析
            writeFile("协议类型: " + arp.prototype);
            writeFile("源协议地址和MAC地址: " + arp.getSenderProtocolAddress() + " -- " + arp.getSenderHardwareAddress());
            writeFile("目的协议地址和MAC地址： " + arp.getTargetProtocolAddress() + " -- " + arp.getTargetHardwareAddress());
            writeFile("数据报长度: " + arp.caplen);
            writeFile("长度: " + arp.len);
            writeFile("时间戳(秒): " + arp.sec);
            writeFile("时间戳(微妙): " + arp.usec);
            writeFile("硬件类型: " + arp.hardtype);
            writeFile("硬件地址长度: " + arp.hlen);
            writeFile("操作: " + arp.operation);

            writeFile("ARP请求: " + ARPPacket.ARP_REQUEST);
            writeFile("ARP应答: " + ARPPacket.ARP_REPLY);
            writeFile("EOF: " + ARPPacket.EOF);
            writeFile("硬件类型-帧中继: " + ARPPacket.HARDTYPE_FRAMERELAY);
            writeFile("硬件类型-IEEE802(令牌环)： " + ARPPacket.HARDTYPE_IEEE802);
            writeFile("协议类型-IP: " + ARPPacket.PROTOTYPE_IP);
            writeFile("RARP请求: " + ARPPacket.RARP_REQUEST);
            writeFile("RARP应答: " + ARPPacket.RARP_REPLY);
            writeFile("数据: " + Arrays.toString(arp.data));
            System.out.println();
        }
        long end = System.currentTimeMillis();
        writeFile("代码运行结束时间： " + new Date());
        writeFile("抓取5个数据包耗时 " + (end - start) + "毫秒");
        System.out.println();
    }

    /**
     * 开启网卡准备抓包
     *
     * @throws Exception
     */
    public static JpcapCaptor openDevice(NetworkInterface device) throws Exception {

		/*
         *  开启网卡准备抓包
		 *  第一个参数：用于捕获包的网络接口序号
		 *  第二个参数：一次性捕获的最大的字节数 2^16次方字节
		 *  第三个参数：是否为混杂模式
		 *  第四个参数：超时，2秒
		 */
        JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535, true, 2000);
        captor.setFilter("arp", true);
        return captor;
    }

    /**
     * 设置过滤器，设置为抓取某种类型的数据报
     *
     * @param filter 过滤数据包类型
     * @throws IOException
     */
    public static void setFilter(JpcapCaptor captor, String filter) throws IOException {
        captor.setFilter(filter, true);
    }

    /**
     * 进行 ARP 数据包抓取
     *
     * @return
     */
    public static ARPPacket arpCap(JpcapCaptor captor) {
        ARPPacket arp;
        long startTime = System.currentTimeMillis();
        while (true) {
            arp = (ARPPacket) captor.getPacket();
            if (arp != null)
                return arp;
            if (System.currentTimeMillis() - startTime > 10000) {
                return null;
            }
        }
    }

    /**
     * 获取网卡信息
     */
    public static void showNetworkAdapterInfo() {

        // 获取网卡列表
        devices = JpcapCaptor.getDeviceList();

        System.out.println();
        writeFile("========================= 网卡信息 ==========================");

        int i = 1;
        for (NetworkInterface device : devices) {
            String netInterfaceName = device.name;
            String netInterDescription = device.description;
            String dataLinkName = device.datalink_name;
            String dataLinkDesc = device.datalink_description;

            System.out.println();
            writeFile("网卡 " + (i++) + ": " + netInterfaceName + "(" + netInterDescription + ")");
            writeFile("数据链路层信息: " + dataLinkName + "(" + dataLinkDesc + ")");

            // 网络接口地址
            for (NetworkInterfaceAddress addr : device.addresses) {
                InetAddress netInterAddress = addr.address;
                InetAddress netInterSubnet = addr.subnet;
                InetAddress netInterBroadcast = addr.broadcast;

                writeFile("网络接口地址: " + netInterAddress + "  子网掩码: " + netInterSubnet + "  广播地址: " + netInterBroadcast);
            }

            writeFile("MAC地址: ");
            int length = device.mac_address.length;
            int count = 1;

            for (byte b : device.mac_address) {
                System.out.print(Integer.toHexString(b & 0xff));

                if (count++ != length)
                    System.out.print(":");
            }
            System.out.println();
            System.out.println();
        }
    }

    public static void writeFile(String info) {

        System.out.println(info);

        try {
            BufferedWriter out = new BufferedWriter(new FileWriter(fileName, true));
            out.write(info + "\r\n");
            out.flush();
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}