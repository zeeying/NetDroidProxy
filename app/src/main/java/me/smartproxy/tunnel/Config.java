package me.smartproxy.tunnel;

import java.net.InetSocketAddress;

/**
 * Created by zengzheying on 15/12/23.
 */
public abstract class Config {
	public InetSocketAddress ServerAddress;
	public IEncryptor Encryptor;
}
