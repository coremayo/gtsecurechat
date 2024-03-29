package edu.gatech.cc.cs4237.gtsecurechat.test;

import static org.junit.Assert.assertEquals;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.junit.Test;

import edu.gatech.cc.cs4237.gtsecurechat.DummyEncryption;
import edu.gatech.cc.cs4237.gtsecurechat.IStreamCipher;
import edu.gatech.cc.cs4237.gtsecurechat.network.CryptoInputStream;
import edu.gatech.cc.cs4237.gtsecurechat.network.CryptoOutputStream;

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
