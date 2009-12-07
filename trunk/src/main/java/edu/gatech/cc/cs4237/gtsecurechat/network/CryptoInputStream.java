package edu.gatech.cc.cs4237.gtsecurechat.network;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import edu.gatech.cc.cs4237.gtsecurechat.IStreamCipher;

/**
 * 
 * @author corey
 *
 */
public class CryptoInputStream extends BufferedReader {
	
	/**
	 * This string will be prefixed to plain text messages before being 
	 * encrypted and removed after decryption. It is a way to tell if decryption
	 * failed.
	 */
	String code = "Hello";
	
	/**
	 * Instance of a stream cipher that will encrypt and decrypt all traffic.
	 */
	IStreamCipher crypto;
	
	/**
	 * Encrypted input stream.
	 */
	InputStream in;
	
	/**
	 * Creates a new instance that will decrypt all received bytes with the 
	 * supplied cipher instance.
	 * @param in Encrypted input stream
	 * @param crypto Instance of stream cipher class
	 */
	public CryptoInputStream(InputStream in, IStreamCipher crypto) {
		super(new InputStreamReader(in));
		this.in = in;
		this.crypto = crypto;
	}
	
	/**
	 * Decrypts traffic received on the encrypted input stream. Will return one 
	 * line of decrypted plain text as a String.
	 * 
	 * @return One line of plain text.
	 */
	public String readLine() {
		try {
			
			// First four bytes = number of bytes in cipher text
			byte[] lenBytes = new byte[4];
			if (in.read(lenBytes) != lenBytes.length) {
				// This would occur if the TCP connection is terminated.
				throw new IOException("Received too few bytes for message");
			}
			int len = Handshake.byteArrayToInt(lenBytes);
			
			// Next 8 bytes are the IV
			byte[] IV = new byte[8];
			if (in.read(IV) != IV.length) {
				throw new IOException("Received too few bytes for message IV");
			}
			
			// The next n bytes are the cipher text.
			byte[] cipher = new byte[len];
			if (in.read(cipher) != cipher.length) {
				throw new IOException("Received too few bytes for cipher text");
			}
			String plain = crypto.decrypt(cipher, IV);
			
			// Check that our prefix came out correctly.
			if (plain.substring(0, code.length()).equals(code)) {
				return plain.substring(
						code.length(), plain.length());
			} else {
				throw new Exception("Decryption Failed!");
			}
			
		// Network problem occurred
		} catch (IOException e) {
			return null;
			
		// Problems with decryption. Maybe cipher text was tampered with.
		} catch (Exception e) {
			return "";
		}
	}
}
