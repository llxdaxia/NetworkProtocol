package cn.lemon.arp;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;
import java.util.Scanner;

public class ARPCaptor {

    private static JpcapCaptor captor;
    private static NetworkInterface[] devices;
    private static final String fileName = ".\\ARP_info.txt";

    public static void main(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        File file = new File(fileName);
        if(file.exists()){
            file.delete();
        }

        writeFile("代码运行开始时间：" + new Date());

        showNetworkAdapterInfo();

        writeFile("输入打开网卡的序号：");
        Scanner scanner = new Scanner(System.in);

        openDevice(scanner.nextInt() - 1);  //打开网卡
        setFilter("arp");    //设置3过滤ARP数据包

        writeFile("======================== ARP 数据包解析 ========================");
        System.out.println();

        for (int i = 0; i < 15; i++) { // 包的数量为 5
            ARPPacket arp = arpCap();
            EthernetPacket e = (EthernetPacket) arp.datalink;

            writeFile("-------------- 包 " + (i + 1) + "--------------");
            System.out.println();

            // EthernetPacket
            String sourceAddress = e.getSourceAddress();
            String destinationAddress = e.getDestinationAddress();
            short frameType = e.frametype;

            writeFile("源MAC地址: " + sourceAddress);
            writeFile("目的MAC地址: " + destinationAddress);
            writeFile("帧类型: " + frameType);

            // arp 内容解析
            short protoType = arp.prototype;
            Object senderProtocolAddress = arp.getSenderProtocolAddress();
            Object senderHardwareAddress = arp.getSenderHardwareAddress();
            Object targetProtocolAddress = arp.getTargetProtocolAddress();
            Object targetHardewareAddress = arp.getTargetHardwareAddress();
            int capturedLength = arp.caplen;
            int packetLength = arp.len;
            long timestamp_s = arp.sec;
            long timestamp_us = arp.usec;
            short hardType = arp.hardtype;
            short hardLength = arp.hlen;
            short operation = arp.operation;

            short arpRequest = ARPPacket.ARP_REQUEST;
            short arpReply = ARPPacket.ARP_REPLY;
            Packet eof = ARPPacket.EOF;
            short frameRelay = ARPPacket.HARDTYPE_FRAMERELAY;
            short tokenRing = ARPPacket.HARDTYPE_IEEE802;
            short protoIP = ARPPacket.PROTOTYPE_IP;
            short rarpRequest = ARPPacket.RARP_REQUEST;
            short rarpReply = ARPPacket.RARP_REPLY;
            String data = new String(arp.data);

            writeFile("协议类型: " + protoType);
            writeFile("源协议地址和MAC地址: " + senderProtocolAddress + " -- " + senderHardwareAddress);
            writeFile("目的协议地址和MAC地址： " + targetProtocolAddress + " -- " + targetHardewareAddress);
            writeFile("数据报长度: " + capturedLength);
            writeFile("长度: " + packetLength);
            writeFile("时间戳(秒): " + timestamp_s);
            writeFile("时间戳(微妙): " + timestamp_us);
            writeFile("硬件类型: " + hardType);
            writeFile("硬件地址长度: " + hardLength);
            writeFile("操作: " + operation);

            writeFile("ARP请求: " + arpRequest);
            writeFile("ARP应答: " + arpReply);
            writeFile("EOF: " + eof);
            writeFile("硬件类型-帧中继: " + frameRelay);
            writeFile("硬件类型-IEEE802(令牌环)： " + tokenRing);
            writeFile("协议类型-IP: " + protoIP);
            writeFile("RARP请求: " + rarpRequest);
            writeFile("RARP应答: " + rarpReply);
            writeFile("数据: " + data);
            System.out.println();
        }

        long end = System.currentTimeMillis();
        System.out.println();
        writeFile("代码运行结束时间： " + new Date());
        writeFile("抓取5个数据包耗时 " + (end - start) + "毫秒");
    }

    /**
     * 开启网卡准备抓包
     *
     * @throws Exception
     */
    public static void openDevice(int deviceNum) throws Exception {

		/*
         *  开启网卡准备抓包
		 *  第一个参数：用于捕获包的网络接口序号
		 *  第二个参数：一次性捕获的最大的字节数 2^16次方字节
		 *  第三个参数：是否为混杂模式
		 *  第四个参数：超时，2秒
		 */
        captor = JpcapCaptor.openDevice(devices[deviceNum], 65535, true, 2000);
    }

    /**
     * 设置过滤器，设置为抓取某种类型的数据报
     *
     * @param filter 过滤数据包类型
     * @throws IOException
     */
    public static void setFilter(String filter) throws IOException {
        captor.setFilter(filter, true);
    }

    /**
     * 进行 ARP 数据包抓取
     *
     * @return
     */
    public static ARPPacket arpCap() {
        ARPPacket arp;
        while (true) {
            arp = (ARPPacket) captor.getPacket();
            if (arp != null)
                return arp;
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
        System.out.println();

        int i = 1;
        for (NetworkInterface device : devices) {
            String netInterfaceName = device.name;
            String netInterDescription = device.description;
            String dataLinkName = device.datalink_name;
            String dataLinkDesc = device.datalink_description;

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