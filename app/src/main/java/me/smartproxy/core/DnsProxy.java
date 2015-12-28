package me.smartproxy.core;

import android.util.SparseArray;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;

import me.smartproxy.dns.DnsPacket;
import me.smartproxy.dns.Question;
import me.smartproxy.dns.Resource;
import me.smartproxy.dns.ResourcePointer;
import me.smartproxy.tcpip.CommonMethods;
import me.smartproxy.tcpip.IPHeader;
import me.smartproxy.tcpip.UDPHeader;
import me.smartproxy.util.DebugLog;

/**
 * Created by zengzheying on 15/12/23.
 */
public class DnsProxy implements Runnable {

	private static final ConcurrentHashMap<Integer, String> IPDomainMaps = new ConcurrentHashMap<Integer, String>();
	private static final ConcurrentHashMap<String, Integer> DomainIPMaps = new ConcurrentHashMap<String, Integer>();
	private final long QUERY_TIMEOUT_NS = 10 * 1000000000L;
	public boolean Stopped;
	private DatagramSocket m_Client;
	private Thread m_ReceivedThread;
	private short m_QueryID;
	private SparseArray<QueryState> m_QueryArray;

	public DnsProxy() throws IOException {
		m_QueryArray = new SparseArray<QueryState>();
		m_Client = new DatagramSocket(0);
	}

	/**
	 * 根据IP查询域名
	 *
	 * @param ip ip地址
	 * @return 对应的域名
	 */
	public static String reverseLookup(int ip) {
		return IPDomainMaps.get(ip);
	}

	/**
	 * 启动线程
	 */
	public void start() {
		m_ReceivedThread = new Thread(this);
		m_ReceivedThread.setName("DnsProxyThread");
		m_ReceivedThread.start();
	}

	/**
	 * 停止线程
	 */
	public void stop() {
		Stopped = true;
		if (m_Client != null) {
			m_Client.close();
			m_Client = null;
		}
	}

	@Override
	public void run() {
		try {
			byte[] RECEIVE_BUFFER = new byte[2000];
			IPHeader ipHeader = new IPHeader(RECEIVE_BUFFER, 0);
			ipHeader.Default();
			//offset 20 --> IP数据报头部长度为20字节
			UDPHeader udpHeader = new UDPHeader(RECEIVE_BUFFER, 20);

			ByteBuffer dnsBuffer = ByteBuffer.wrap(RECEIVE_BUFFER);
			// 28：IP数据报头部20字节 + UDP数据报头部8字节
			dnsBuffer.position(28);
			dnsBuffer = dnsBuffer.slice();

			DatagramPacket packet = new DatagramPacket(RECEIVE_BUFFER, 28, RECEIVE_BUFFER.length - 28);

			while (m_Client != null && !m_Client.isClosed()) {

				packet.setLength(RECEIVE_BUFFER.length - 28);
				m_Client.receive(packet);

				dnsBuffer.clear();
				dnsBuffer.limit(packet.getLength());
				try {
					DnsPacket dnsPacket = DnsPacket.FromBytes(dnsBuffer);
					if (dnsPacket != null) {
						OnDnsResponseReceived(ipHeader, udpHeader, dnsPacket);
					}
				} catch (Exception e) {
					e.printStackTrace();
					LocalVpnService.Instance.writeLog("Parse dns error: %s", e);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
//			System.out.println("DnsResolver Thread Exited.");
			if (ProxyConfig.IS_DEBUG) {
				DebugLog.i("DnsResolver Thread Exited.");
			}
			this.stop();
		}
	}

	/**
	 * 从DNS报文中获取第一个IP地址
	 *
	 * @param dnsPacket DNS回复报文
	 * @return 第一个IP地址，没有则返回0
	 */
	private int getFirstIP(DnsPacket dnsPacket) {
		for (int i = 0; i < dnsPacket.Header.ResourceCount; i++) {
			Resource resource = dnsPacket.Resources[i];
			if (resource.Type == 1) {
				int ip = CommonMethods.readInt(resource.Data, 0);
				return ip;
			}
		}
		return 0;
	}

	/**
	 * 修改DNS数据包中的IP地址
	 * @param rawPacket 数据缓冲区数组
	 * @param dnsPacket rawPacket包含的DNS报文
	 * @param newIP 新的IP地址
	 */
	private void tamperDnsResponse(byte[] rawPacket, DnsPacket dnsPacket, int newIP) {
		Question question = dnsPacket.Questions[0]; //DNS包的第一个问题

		dnsPacket.Header.setResourceCount((short) 1);
		dnsPacket.Header.setAResourceCount((short) 0);
		dnsPacket.Header.setEResourceCount((short) 0);

		// 这里会有个疑问，在DNS报文中，只有头部是固定的，其他部分不一定，这个方法在DNS查询、回复中都有用到，
		// 理论上应该出现数组控件不足的情况吧（查询的DNS包只有头部部分）
		// 那么怎么这里的处理不用按情况分别增加数组空间呢？

		// 其实在DNS查询的时候，这里的rawPacket时LocalVpnService的m_Packet数组的空间
		// 在DNS回复的时候，这里的rawPacket其实是本类run方法的RECEIVE_BUFFER数组的空间
		// 两者的空间都足够大，所以不用增加数组空间

		ResourcePointer rPointer = new ResourcePointer(rawPacket, question.Offset() + question.Length());
		rPointer.setDomain((short) 0xC00C);
		rPointer.setType(question.Type);
		rPointer.setClass(question.Class);
		rPointer.setTTL(ProxyConfig.Instance.getDnsTTL());
		rPointer.setDataLength((short) 4);
		rPointer.setIP(newIP);

		// DNS报头长度 + 问题长度 + 资源记录长度（域名指针[2字节] + 类型[2字节] +
		// 类[2字节] + TTL[4字节] + 资源数据长度[2字节] + ip[4字节] = 16字节）
		dnsPacket.Size = 12 + question.Length() + 16;
	}

	/**
	 * 获取或创建一个指定域名的IP地址
	 * @param domainString 指定域名
	 * @return ip地址
	 */
	private int getOrCreateFakeIP(String domainString) {
		Integer fakeIP = DomainIPMaps.get(domainString);
		if (fakeIP == null) {
			int hashIP = domainString.hashCode();
			do {
				fakeIP = ProxyConfig.FAKE_NETWORK_IP | (hashIP & 0x0000FFFF);
				hashIP++;
			} while (IPDomainMaps.containsKey(fakeIP));

			DomainIPMaps.put(domainString, fakeIP);
			IPDomainMaps.put(fakeIP, domainString);
		}
		return fakeIP;
	}

	/**
	 * 对收到的DNS答复进行修改，以达到DNS污染的目的
	 * @param rawPacket ip包的数据部分
	 * @param dnsPacket DNS数据包
	 * @return true: 修改了数据 false: 未修改数据
	 */
	private boolean dnsPollution(byte[] rawPacket, DnsPacket dnsPacket) {
		if (dnsPacket.Header.QuestionCount > 0) {
			Question question = dnsPacket.Questions[0];
			if (question.Type == 1) {
				int realIP = getFirstIP(dnsPacket);
				// 对需要代理的域名和ip进行污染
				// *为了调试，全部污染
				if (ProxyConfig.Instance.needProxy(question.Domain, realIP) || ProxyConfig.IS_DEBUG) {
					int fakeIP = getOrCreateFakeIP(question.Domain); // 获取或创建一个虚假ip
					tamperDnsResponse(rawPacket, dnsPacket, fakeIP); // 修改包数据
					if (ProxyConfig.IS_DEBUG) {
						DebugLog.i("FakeDns: %s=>%s(%s)\n", question.Domain, CommonMethods.ipIntToString
								(realIP), CommonMethods.ipIntToString(fakeIP));
					}
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * 收到Dns查询回复，对指定域名进行污染后，转发给发起请求的客户端
	 */
	private void OnDnsResponseReceived(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
		QueryState state = null;
		synchronized (m_QueryArray) {
			state = m_QueryArray.get(dnsPacket.Header.ID);
			if (state != null) {
				m_QueryArray.remove(dnsPacket.Header.ID);
			}
		}

		if (state != null) {
			//DNS污染，默认污染海外网站
			dnsPollution(udpHeader.m_Data, dnsPacket);

			dnsPacket.Header.setID(state.ClientQueryID);
			ipHeader.setSourceIP(state.RemoteIP);
			ipHeader.setDestinationIP(state.ClientIP);
			ipHeader.setProtocol(IPHeader.UDP);
			// IP头部长度 + UDP头部长度 + DNS报文长度
			ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
			udpHeader.setSourcePort(state.RemotePort);
			udpHeader.setDestinationPort(state.ClientPort);
			udpHeader.setTotalLength(8 + dnsPacket.Size);

			LocalVpnService.Instance.sendUDPPacket(ipHeader, udpHeader);
		}
	}

	/**
	 * 从缓冲中获取指定的域名的IP
	 * @param domain 指定域名
	 * @return 域名的IP地址
	 */
	private int getIPFromCache(String domain) {
		Integer ip = DomainIPMaps.get(domain);
		if (ip == null) {
			return 0;
		} else {
			return ip;
		}
	}

	/**
	 * 对符合过滤条件的域名（如是海外域名或者是gfw上的拦截域名），则直接构建一个提供虚假IP的DNS回复包
	 * @param ipHeader ip报文
	 * @param udpHeader udp报文
	 * @param dnsPacket dns报文
	 * @return 构建了一个虚假的DNS回复包给查询客户端则返回true，否则false
	 */
	private boolean interceptDns(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
		Question question = dnsPacket.Questions[0];
//		System.out.println("DNS Qeury " + question.Domain);
		if (ProxyConfig.IS_DEBUG) {
			DebugLog.i("DNS query %s", question.Domain);
		}
		if (question.Type == 1) {
			// 判断域名是否需要通过代理
			// *这里为了调试，全部域名都进行代理
			if (ProxyConfig.Instance.needProxy(question.Domain, getIPFromCache(question.Domain)) || ProxyConfig.IS_DEBUG) {
				int fakeIP = getOrCreateFakeIP(question.Domain);
				// 修改IP包数据
				tamperDnsResponse(ipHeader.m_Data, dnsPacket, fakeIP);

				if (ProxyConfig.IS_DEBUG) {
					DebugLog.i("interceptDns FakeDns: %s=>%s\n", question.Domain, CommonMethods.ipIntToString
							(fakeIP));
				}

				int sourceIP = ipHeader.getSourceIP();  //DNS查询客户端的ip地址
				short sourcePort = udpHeader.getSourcePort(); //DNS查询客户端的端口
				ipHeader.setSourceIP(ipHeader.getDestinationIP()); //欺骗客户端该报文是由它所查询的DNS服务器发过来的
				ipHeader.setDestinationIP(sourceIP); //设置目的IP为客户端的ip地址
				//IP数据包数据长度 = ip数据报报头长度 + udp报头长度 + DNS报文长度
				ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
				udpHeader.setSourcePort(udpHeader.getDestinationPort());  //设置源端口为客户端所查询的DNS服务器端口号
				udpHeader.setDestinationPort(sourcePort); //设置目的端口为客户端的端口
				udpHeader.setTotalLength(8 + dnsPacket.Size); //UDP报文长度 = UDP报头长度 + DNS报文长度
				LocalVpnService.Instance.sendUDPPacket(ipHeader, udpHeader); //发送数据包
				return true;
			}
		}
		return false;
	}

	/**
	 * 清除超时的查询
	 */
	private void clearExpiredQueries() {
		long now = System.nanoTime();
		for (int i = m_QueryArray.size() - 1; i >= 0; i--) {
			QueryState state = m_QueryArray.valueAt(i);
			if ((now - state.QueryNanoTime) > QUERY_TIMEOUT_NS) {
				m_QueryArray.removeAt(i);
			}
		}
	}

	/**
	 * 收到APPs的DNS查询包，根据情况转发或者提供一个虚假的DNS回复数据报
	 */
	public void onDnsRequestReceived(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
		//如果不是海外域名（或者说符合过滤条件）的查询，那么将由DnsProxy转发到DNS服务器上，查询真实ip
		if (!interceptDns(ipHeader, udpHeader, dnsPacket)) {
			//转发DNS
			QueryState state = new QueryState();
			state.ClientQueryID = dnsPacket.Header.ID;
			state.QueryNanoTime = System.nanoTime();
			state.ClientIP = ipHeader.getSourceIP();
			state.ClientPort = udpHeader.getSourcePort();
			state.RemoteIP = ipHeader.getDestinationIP();
			state.RemotePort = udpHeader.getDestinationPort();

			// 转换QueryID
			m_QueryID++;// 增加ID
			dnsPacket.Header.setID(m_QueryID);

			synchronized (m_QueryArray) {
				clearExpiredQueries();//清空过期的查询，减少内存开销。
				m_QueryArray.put(m_QueryID, state);// 关联数据
			}

			//应该是DNS服务器地址和端口
			InetSocketAddress remoteAddress = new InetSocketAddress(CommonMethods.ipIntToInet4Address(state.RemoteIP),
					state.RemotePort);
			//只把DNS数据包发送过去，不包含UDP的报头部分
			DatagramPacket packet = new DatagramPacket(udpHeader.m_Data, udpHeader.m_Offset + 8, dnsPacket.Size);
			packet.setSocketAddress(remoteAddress);

			try {
				if (LocalVpnService.Instance.protect(m_Client)) {
					//使用DatagramSocket发送DatagramPacket，读取也是用该DatagramSocket
					m_Client.send(packet);
				} else {
					if (ProxyConfig.IS_DEBUG) {
						DebugLog.e("VPN protect udp socket failed.");
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private class QueryState {
		public short ClientQueryID;
		public long QueryNanoTime;
		public int ClientIP;
		public short ClientPort;
		public int RemoteIP;
		public short RemotePort;
	}

}
