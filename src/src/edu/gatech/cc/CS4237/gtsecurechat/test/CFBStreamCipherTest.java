package edu.gatech.cc.CS4237.gtsecurechat.test;

import junit.framework.Assert;

import org.junit.Test;

import edu.gatech.cc.CS4237.gtsecurechat.CFBStreamCipher;
import edu.gatech.cc.CS4237.gtsecurechat.IDEABlockCipher;

public class CFBStreamCipherTest {

	private byte[] key = {0x73, 0x68, 0x23, 0x20, 0x40, 0x33, 0x3F, 0x48, 0x3E, 0x0D, 0x77, 0x39, 0x52, 0x7D, 0x1E, 0x00,};
	private byte[] IV = {0x33, 0x3E, 0x65, 0x12, 0x4C, 0x05, 0x7F, 0x2E};
	String clear = "This is a secret message.  Don't let the enemy get it!";
	
	@Test
	public void testEncrypt() {
		CFBStreamCipher cipher = new CFBStreamCipher(new IDEABlockCipher());
		cipher.initialize(key);
		
		cipher.encrypt(clear, IV);
	}

	@Test
	public void testDecrypt() {
		CFBStreamCipher cipher = new CFBStreamCipher(new IDEABlockCipher());
		cipher.initialize(key);
		
		byte[] cipherText = cipher.encrypt(clear, IV);
		String output = cipher.decrypt(cipherText, IV);
		Assert.assertEquals(clear, output);
	}

}
