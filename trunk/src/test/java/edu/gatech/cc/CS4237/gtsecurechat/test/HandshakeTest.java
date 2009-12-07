package edu.gatech.cc.CS4237.gtsecurechat.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import edu.gatech.cc.CS4237.gtsecurechat.network.Handshake;

public class HandshakeTest {

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
		
		assertEquals(keyAlice.length, 16);
		assertEquals(keyBob.length, 16);
		assertArrayEquals(keyAlice, keyBob);
	}
}
