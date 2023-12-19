package com.ouc.tcp.test;

import com.ouc.tcp.message.TCP_PACKET;
import com.ouc.tcp.message.TCP_HEADER;

import java.util.ArrayList;

public class CheckSum {
	
	/*计算TCP报文段校验和：只需校验TCP首部中的seq、ack和sum，以及TCP数据字段*/
	public static short computeChkSum(TCP_PACKET tcpPack) {
		final int tcpProtocolId = 6;
		// 计算校验和的准备阶段
		byte[] srcAddr = tcpPack.getSourceAddr().getAddress(); // 伪首部的源IP地址
		byte[] desAddr = tcpPack.getDestinAddr().getAddress(); // 伪首部的目的IP地址
		TCP_HEADER tcpH = tcpPack.getTcpH(); // TCP 的首部
		ArrayList<Integer> arr = new ArrayList<Integer>();
		// 所有内容按照两字节对齐
		arr.add(bytes2int(srcAddr[0], srcAddr[1]));
		arr.add(bytes2int(srcAddr[2], srcAddr[3]));
		arr.add(bytes2int(desAddr[0], desAddr[1]));
		arr.add(bytes2int(desAddr[2], desAddr[3]));
		arr.add(tcpProtocolId);
		arr.add(tcpPack.getTCP_Length());
		arr.add(tcpH.getTh_seq());
		arr.add(tcpH.getTh_ack());
		arr.add((int) tcpH.getTh_sum());
		arr.add(0); // 不加这个补充的0 在空数据的时候算出来的checkSum为1
		// 将数据部分也分别按照两字节对齐
		for(int data : tcpPack.getTcpS().getData()){
			int t = 0;
			t |= data >>> 16; // 数据部分的高两字节
			arr.add(t);
			t &= data & 0x0000ffff; // 数据部分的低两字节
			arr.add(t);
		}
		// 开始计算 checkSum int为四个字节，所以一定会两字节两字节的对齐
		int checkSum = 0;
		for(int num:arr) {
			checkSum += num;
			if(checkSum>>>16>0) {
				checkSum = (checkSum >>> 16) + (checkSum & 0xffff);
			}
		}
		checkSum = ~checkSum;
		System.out.println(Integer.toBinaryString(checkSum));
		//取低16位
		System.out.println(Integer.toHexString(checkSum).substring(4));
		
		
		return (short) checkSum;
	}

	/**
	 * 将两个byte 转换为只有低16位有内容的int，本方法适用于(高位在前，低位在后)的顺序
	 */
	public static int bytes2int(byte byteH, byte byteL) {
		int result = 0;
		result |= byteH;
		result <<= 8;
		result |= byteL;
		return result;
	}
}
