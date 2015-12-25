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

	private void tamperDnsResponse(byte[] rawPacket, DnsPacket dnsPacket, int newIP) {
		Question question = dnsPacket.Questions[0];

		dnsPacket.Header.setResourceCount((short) 1);
		dnsPacket.Header.setAResourceCount((short) 0);
		dnsPacket.Header.setEResourceCount((short) 0);

		ResourcePointer rPointer = new ResourcePointer(rawPacket, question.Offset() + question.Length());
		rPointer.setDomain((short) 0xC00C);
		rPointer.setType(question.Type);
		rPointer.setClass(question.Class);
		rPointer.setTTL(ProxyConfig.Instance.getDnsTTL());
		rPointer.setDataLength((short) 4);
		rPointer.setIP(newIP);

		dnsPacket.Size = 12 + question.Length() + 16;
	}

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

	private boolean dnsPollution(byte[] rawPacket, DnsPacket dnsPacket) {
		if (dnsPacket.Header.QuestionCount > 0) {
			Question question = dnsPacket.Questions[0];
			if (question.Type == 1) {
				int realIP = getFirstIP(dnsPacket);
				//加调试，国内流量也进行DNS污染
				if (ProxyConfig.Instance.needProxy(question.Domain, realIP) || ProxyConfig.IS_DEBUG) {
					int fakeIP = getOrCreateFakeIP(question.Domain);
					tamperDnsResponse(rawPacket, dnsPacket, fakeIP);
					if (ProxyConfig.IS_DEBUG) {
//						System.out.printf("FakeDns: %s=>%s(%s)\n", question.Domain, CommonMethods.ipIntToString
//								(realIP), CommonMethods.ipIntToString(fakeIP));

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
	 * 收到Dns查询回复，转发给发起请求的客户端
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

	private int getIPFromCache(String domain) {
		Integer ip = DomainIPMaps.get(domain);
		if (ip == null) {
			return 0;
		} else {
			return ip;
		}
	}

	private boolean interceptDns(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
		Question question = dnsPacket.Questions[0];
//		System.out.println("DNS Qeury " + question.Domain);
		if (ProxyConfig.IS_DEBUG) {
			DebugLog.i("DNS query %s", question.Domain);
		}
		if (question.Type == 1) {
			if (ProxyConfig.Instance.needProxy(question.Domain, getIPFromCache(question.Domain)) || ProxyConfig.IS_DEBUG) {
				int fakeIP = getOrCreateFakeIP(question.Domain);
				tamperDnsResponse(ipHeader.m_Data, dnsPacket, fakeIP);

				if (ProxyConfig.IS_DEBUG) {
//					System.out.printf("interceptDns FakeDns: %s=>%s\n", question.Domain, CommonMethods.ipIntToString
//							(fakeIP));
					DebugLog.i("interceptDns FakeDns: %s=>%s\n", question.Domain, CommonMethods.ipIntToString
							(fakeIP));
				}

				int sourceIP = ipHeader.getSourceIP();
				short sourcePort = udpHeader.getSourcePort();
				ipHeader.setSourceIP(ipHeader.getDestinationIP());
				ipHeader.setDestinationIP(sourceIP);
				ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
				udpHeader.setSourcePort(udpHeader.getDestinationPort());
				udpHeader.setDestinationPort(sourcePort);
				udpHeader.setTotalLength(8 + dnsPacket.Size);
				LocalVpnService.Instance.sendUDPPacket(ipHeader, udpHeader);
				return true;
			}
		}
		return false;
	}

	private void clearExpiredQueries() {
		long now = System.nanoTime();
		for (int i = m_QueryArray.size() - 1; i >= 0; i--) {
			QueryState state = m_QueryArray.valueAt(i);
			if ((now - state.QueryNanoTime) > QUERY_TIMEOUT_NS) {
				m_QueryArray.removeAt(i);
			}
		}
	}

	public void onDnsRequestReceived(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
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

			InetSocketAddress remoteAddress = new InetSocketAddress(CommonMethods.ipIntToInet4Address(state.RemoteIP),
					state.RemotePort);
			DatagramPacket packet = new DatagramPacket(udpHeader.m_Data, udpHeader.m_Offset + 8, dnsPacket.Size);
			packet.setSocketAddress(remoteAddress);

			try {
				if (LocalVpnService.Instance.protect(m_Client)) {
					m_Client.send(packet);
				} else {
//					System.err.println("VPN protect udp socket failed.");
					if (ProxyConfig.IS_DEBUG) {
						DebugLog.e("VPN protect udp socket failed.");
					}
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
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
