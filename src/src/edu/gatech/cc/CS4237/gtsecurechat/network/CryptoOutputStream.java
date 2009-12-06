package edu.gatech.cc.CS4237.gtsecurechat.network;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.SecureRandom;

import edu.gatech.cc.CS4237.gtsecurechat.IStreamCipher;

/**
 * 
 * @author corey
 *
 */
public class CryptoOutputStream extends PrintWriter {
	
	IStreamCipher crypto;
	SecureRandom rand;
	OutputStream out;
	
	/**
	 * Creates a new instance that will encrypt all messages that are sent using
	 * the println method and will send to the supplied output stream.
	 * @param out Stream which encrypted traffic will be sent over
	 * @param key Encryption key.
	 */
	public CryptoOutputStream(OutputStream out, IStreamCipher crypto) {
		super(out, true);
		this.out = out;
		this.crypto = crypto;
		rand = new SecureRandom();
	}

	/**
	 * Encrypts the supplied String then sends it to the OutputStream.<br />
	 * What it sends:<br />
	 * <ul>
	 * <li>4 bytes - total number of bytes in cipher text message</li>
	 * <li>8 bytes - initialization vector</li>
	 * <li>n bytes - the cipher text message</li>
	 * </li>
	 * @param plain Plain text message to be encrypted and sent
	 */
	public void println(String plain) {
		byte[] IV = new byte[8];
		rand.nextBytes(IV);
		byte[] cipher = crypto.encrypt(plain, IV);
		byte[] len = Handshake.intToByteArray(cipher.length);
		
		try {
			out.write(len);
			out.write(IV);
			out.write(cipher);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
