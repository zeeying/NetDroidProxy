package me.smartproxy.tunnel;

import java.nio.ByteBuffer;

/**
 * Created by zengzheying on 15/12/23.
 */
public interface IEncryptor {

	void encrypt(ByteBuffer buffer);

	void decrypt(ByteBuffer buffer);

}
