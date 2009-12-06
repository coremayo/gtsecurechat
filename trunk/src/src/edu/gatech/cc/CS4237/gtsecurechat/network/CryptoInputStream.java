package edu.gatech.cc.CS4237.gtsecurechat.network;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import edu.gatech.cc.CS4237.gtsecurechat.IStreamCipher;

public class CryptoInputStream extends BufferedReader {
	
	IStreamCipher crypto;
	InputStream in;
	
	public CryptoInputStream(InputStream in, IStreamCipher crypto) {
		super(new InputStreamReader(in));
		this.in = in;
		this.crypto = crypto;
	}
	
	public String readLine() {
		try {
			byte[] lenBytes = new byte[4];
			if (in.read(lenBytes) != lenBytes.length) {
				throw new Exception("Received too few bytes for message");
			}
			int len = Handshake.byteArrayToInt(lenBytes);
			
			byte[] IV = new byte[8];
			if (in.read(IV) != IV.length) {
				throw new Exception("Received too few bytes for message IV");
			}
			
			byte[] cipher = new byte[len];
			if (in.read(cipher) != cipher.length) {
				throw new Exception("Received too few bytes for cipher");
			}
			String plain = crypto.decrypt(cipher, IV);
			return plain;
			
		} catch (Exception e) {
			return null;
		}
	}
}
