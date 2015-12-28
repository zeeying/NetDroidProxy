package me.smartproxy.core;

import android.util.SparseArray;

import me.smartproxy.tcpip.CommonMethods;

/**
 * Created by zengzheying on 15/12/23.
 */
public class NatSessionManager {

	static final int MAX_SESSION_COUNT = 60; //会话保存最大个数
	static final long SESSION_TIMEOUT_NS = 60 * 1000000000L; //会话保存时间
	static final SparseArray<NatSession> Sessions = new SparseArray<NatSession>();

	/**
	 * 通过端口获取会话
	 *
	 * @param portKey 端口号
	 * @return NatSession会话对象
	 */
	public static NatSession getSession(int portKey) {
		return Sessions.get(portKey);
	}

	/**
	 * 获取会话个数
	 * @return 会话个数
	 */
	public static int getSessionCount() {
		return Sessions.size();
	}

	/**
	 * 清除过期的会话
	 */
	static void clearExpiredSessions() {
		long now = System.nanoTime();
		for (int i = Sessions.size() - 1; i >= 0; i--) {
			NatSession session = Sessions.valueAt(i);
			if (now - session.LastNanoTime > SESSION_TIMEOUT_NS) {
				Sessions.removeAt(i);
			}
		}
	}

	/**
	 * 创建会话
	 * @param portKey 源端口
	 * @param remoteIP 远程ip
	 * @param remotePort 远程端口
	 * @return NatSession对象
	 */
	public static NatSession createSession(int portKey, int remoteIP, short remotePort) {
		if (Sessions.size() > MAX_SESSION_COUNT) {
			clearExpiredSessions();//清理过期的会话。
		}

		NatSession session = new NatSession();
		session.LastNanoTime = System.nanoTime();
		session.RemoteIP = remoteIP;
		session.RemotePort = remotePort;

		if (ProxyConfig.isFakeIP(remoteIP)) {
			session.RemoteHost = DnsProxy.reverseLookup(remoteIP);
		}

		if (session.RemoteHost == null) {
			session.RemoteHost = CommonMethods.ipIntToString(remoteIP);
		}
		Sessions.put(portKey, session);
		return session;
	}

}
