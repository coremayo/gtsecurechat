package edu.gatech.cc.CS4237.gtsecurechat.network;

import static org.junit.Assert.assertEquals;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.junit.Test;

import edu.gatech.cc.CS4237.gtsecurechat.DummyEncryption;
import edu.gatech.cc.CS4237.gtsecurechat.IStreamCipher;

public class CryptoStreamTest {

	@Test
	public void testCryptoStream() throws Exception {
		String original = "Test123";
		String received;
		IStreamCipher crypto;
		CryptoInputStream cryptoIn;
		CryptoOutputStream cryptoOut;
		PipedInputStream in;
		PipedOutputStream out;
		
		crypto = new DummyEncryption();
		out = new PipedOutputStream();
		in = new PipedInputStream(out);
		cryptoOut = new CryptoOutputStream(out, crypto);
		cryptoIn = new CryptoInputStream(in, crypto);
		
		cryptoOut.println(original);
		received = cryptoIn.readLine();
		
		assertEquals(original, received);
	}
}
