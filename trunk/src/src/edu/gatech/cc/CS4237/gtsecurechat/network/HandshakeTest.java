package edu.gatech.cc.CS4237.gtsecurechat.network;

import static org.junit.Assert.*;

import org.junit.Test;

public class HandshakeTest {

//	public HandshakeTest() {
//		super("alice", "bob", new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'});
//	}

	@Test
	public void testHandshake() throws Exception {
		char[] pass = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
		Handshake alice, bob;
		alice = new Handshake("alice", "bob", pass);
		bob = new Handshake("alice", "bob", pass);
		
		byte[] m1, m2, m3;
		m1 = alice.m1();
		m2 = bob.m2(m1);
		m3 = alice.m3(m2);
		bob.m4(m3);
		
		byte[] keyAlice, keyBob;
		keyAlice = alice.getKey();
		keyBob = bob.getKey();
		
		System.out.println("Alice got key 0x" + 
				Handshake.byteArrayToHexString(keyAlice));
		System.out.println("  Bob got key 0x" + 
				Handshake.byteArrayToHexString(keyBob));
		
		assertEquals(keyAlice.length, 16);
		assertEquals(keyBob.length, 16);
		assertArrayEquals(keyAlice, keyBob);
	}
}
