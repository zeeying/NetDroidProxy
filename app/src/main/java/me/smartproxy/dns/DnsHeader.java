package me.smartproxy.dns;

import java.nio.ByteBuffer;

import me.smartproxy.tcpip.CommonMethods;

/**
 * Created by zengzheying on 15/12/23.
 */
public class DnsHeader {

	/**
	 * 说明一下：并不是所有DNS报文都有以上各个部分的。图中标示的“12字节”为DNS首部，这部分肯定都会有
	 * 首部下面的是正文部分，其中查询问题部分也都会有。
	 * 除此之外，回答、授权和额外信息部分是只出现在DNS应答报文中的，而这三部分又都采用资源记录（Recource Record）的相同格式
	 * ０　　　　　　　　　　　１５　　１６　　　　　　　　　　　　３１
	 * 　	 ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜　　－－
	 * ｜          标识          ｜           标志           ｜　　  ｜
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜     ｜
	 * ｜         问题数         ｜        资源记录数         ｜　　１２字节
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜    　｜
	 * ｜　    授权资源记录数     ｜      额外资源记录数        ｜     ｜
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜　　－－
	 * ｜　　　　　　　　      查询问题                        ｜
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
	 * ｜                      回答                         ｜
	 * ｜　             （资源记录数可变）                    ｜
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
	 * ｜                      授权                         ｜
	 * ｜               （资源记录数可变）                    ｜
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
	 * ｜                  　额外信息                       ｜
	 * ｜               （资源记录数可变）                    ｜
	 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
	 */

	static final short offset_ID = 0;
	static final short offset_Flags = 2;
	static final short offset_QuestionCount = 4;
	static final short offset_ResourceCount = 6;
	static final short offset_AResourceCount = 8;
	static final short offset_EResourceCount = 10;
	public short ID;
	public DnsFlags Flags;
	public short QuestionCount;
	public short ResourceCount;
	public short AResourceCount;
	public short EResourceCount;
	public byte[] Data;
	public int Offset;

	public DnsHeader(byte[] data, int offset) {
		this.Offset = offset;
		this.Data = data;
	}

	public static DnsHeader FromBytes(ByteBuffer buffer) {
		DnsHeader header = new DnsHeader(buffer.array(), buffer.arrayOffset() + buffer.position());
		header.ID = buffer.getShort();
		header.Flags = DnsFlags.Parse(buffer.getShort());
		header.QuestionCount = buffer.getShort();
		header.ResourceCount = buffer.getShort();
		header.AResourceCount = buffer.getShort();
		header.EResourceCount = buffer.getShort();
		return header;
	}

	public void ToBytes(ByteBuffer buffer) {
		buffer.putShort(this.ID);
		buffer.putShort(this.Flags.ToShort());
		buffer.putShort(this.QuestionCount);
		buffer.putShort(this.ResourceCount);
		buffer.putShort(this.AResourceCount);
		buffer.putShort(this.EResourceCount);
	}

	public short getID() {
		return CommonMethods.readShort(Data, Offset + offset_ID);
	}

	public void setID(short value) {
		CommonMethods.writeShort(Data, Offset + offset_ID, value);
	}

	public short getFlags() {
		return CommonMethods.readShort(Data, Offset + offset_Flags);
	}

	public void setFlags(short value) {
		CommonMethods.writeShort(Data, Offset + offset_Flags, value);
	}

	public short getQuestionCount() {
		return CommonMethods.readShort(Data, Offset + offset_QuestionCount);
	}

	public void setQuestionCount(short value) {
		CommonMethods.writeShort(Data, Offset + offset_QuestionCount, value);
	}

	public short getResourceCount() {
		return CommonMethods.readShort(Data, Offset + offset_ResourceCount);
	}

	public void setResourceCount(short value) {
		CommonMethods.writeShort(Data, Offset + offset_ResourceCount, value);
	}

	public short getAResourceCount() {
		return CommonMethods.readShort(Data, Offset + offset_AResourceCount);
	}

	public void setAResourceCount(short value) {
		CommonMethods.writeShort(Data, Offset + offset_AResourceCount, value);
	}

	public short getEResourceCount() {
		return CommonMethods.readShort(Data, Offset + offset_EResourceCount);
	}

	public void setEResourceCount(short value) {
		CommonMethods.writeShort(Data, Offset + offset_EResourceCount, value);
	}

}
