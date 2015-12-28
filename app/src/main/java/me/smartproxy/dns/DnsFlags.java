package me.smartproxy.dns;

/**
 * Created by zengzheying on 15/12/23.
 */
public class DnsFlags {

	/**
	 * DNS报文的标志（2字节）
	 *
	 * |-------------------------------------------------|
	 * | QR | opcode  | AA | TC | RD | RA | zero | rcode |
	 * |-------------------------------------------------|
	 *   1       4       1    1    1    1     3       4
	 * <p/>
	 * opcode(4比特)：定义查询或响应的类型（若0则表示是标准的，1表示反向，2则是服务器状态请求）
	 * AA(1比特)：授权回答的标志位。该位在响应报文中有效，1表示名字服务器是权限服务器
	 * TC(1比特)：截断标志位。1表示响应已超过512字节并已被截断
	 * RD(1比特)：该位为1表示客户端希望得到递归回答
	 * RA(1比特)：只能在响应报文中置为1，表示可以得到递归响应
	 * zero(3比特)：为0，保留字段
	 * rcode(4比特)：返回码，表示响应的差错状态，通常为0和3，各取值含义如下：
	 * 0       无差错
	 * 1       格式差错
	 * 2       问题在域名服务器上
	 * 3       域参照问题
	 * 4       查询类型不支持
	 * 5       在管理上被禁止
	 * 6-15    保留
	 */

	public boolean QR;//1 bits
	public int OpCode;//4 bits
	public boolean AA;//1 bits
	public boolean TC;//1 bits
	public boolean RD;//1 bits
	public boolean RA;//1 bits
	public int Zero;//3 bits
	public int Rcode;//4 bits

	public static DnsFlags Parse(short value) {
		int m_Flags = value & 0xFFFF;
		DnsFlags flags = new DnsFlags();
		flags.QR = ((m_Flags >> 7) & 0x01) == 1;
		flags.OpCode = (m_Flags >> 3) & 0x0F;
		flags.AA = ((m_Flags >> 2) & 0x01) == 1;
		flags.TC = ((m_Flags >> 1) & 0x01) == 1;
		flags.RD = (m_Flags & 0x01) == 1;
		flags.RA = (m_Flags >> 15) == 1;
		flags.Zero = (m_Flags >> 12) & 0x07;
		flags.Rcode = ((m_Flags >> 8) & 0xF);
		return flags;
	}

	public short ToShort() {
		int m_Flags = 0;
		m_Flags |= (this.QR ? 1 : 0) << 7;
		m_Flags |= (this.OpCode & 0x0F) << 3;
		m_Flags |= (this.AA ? 1 : 0) << 2;
		m_Flags |= (this.TC ? 1 : 0) << 1;
		m_Flags |= this.RD ? 1 : 0;
		m_Flags |= (this.RA ? 1 : 0) << 15;
		m_Flags |= (this.Zero & 0x07) << 12;
		m_Flags |= (this.Rcode & 0x0F) << 8;
		return (short) m_Flags;
	}

}
