package com.google.code.distributedwpacracking.master.javabeans;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import com.google.code.distributedwpacracking.master.GlobalConstants;
import com.google.code.distributedwpacracking.master.utils.SignedUnsignedNumberConvertor;

/**
 * @author rbeede
 *
 * This is a Java conversion of coWPAtty's cowpatty.h struct hashdb_head as per coWPAtty version 4.6.
 * 
 * <p>
 * For uint8_t endianness of bytes on disk should not affect reading into memory.  For the unit32_t magic it is used
 * for in cowpatty to verify that a file is actually a hash table file.  The special value is found in
 * common.h as the line #define GENPMKMAGIC 0x43575041.  So if we read the endianness wrong this value won't match up.
 * coWPAtty makes no attempt to worry about the endianness when it creates the files, and Java assumes MSB.  magic
 * appears to be in LSB (little endian) order in the actual file.
 * </p>
 * 
 * <p>
 * Note that the struct was define as follows:<br />
 * <pre>
		struct hashdb_head {
			uint32_t magic;
			uint8_t reserved1[3];
			uint8_t ssidlen;
			uint8_t ssid[32];
		};
 * </pre>
 * </p>
 * 
 * <p>Note that ssid[32] doesn't require to contain a '\0' character.  Rely on ssidlen.</p>
 * 
 * <p>
 * Unsigned 8-bit integers are covered by using Java's 32-bit integer which is large enough to not have issues with
 * the sign of the number.
 * </p>
 * 
 * <p>
 * Unsigned 32-bit integers are covered by using Java's 64-bit long which is large enough to not have issues with
 * the sign of the number.
 * </p>
 * 
 * <p>Legal text from cowpatty.h:<br />
 * <pre>
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: cowpatty.h,v 4.3 2008-11-12 14:22:27 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * </pre>
 * </p>
 */
public class HashDatabaseHeader {
	public static final int REQUIRED_BYTE_LENGTH = 4 + 1*3 + 1 + 1*32;
	
	/**
	 * IEEE Std 802.11-2007
	 * 7.3.2.1 SSID element
	 * Page 101
	 */
	public static final int MAXIMUM_SSID_LENGTH = 32;
	
	
	public static final long GENPMKMAGIC = 0x43575041;  // Java's long covers C's uint32_t
	
	// We don't bother to store magic since the constructor verifies it matches GENPMKMAGIC
	
	private final int[] reserved = new int[3];  // not used in coWPAtty currently
	
	private final String ssid;  // covers both ssidlen and ssid
	
	
	/**
	 * @param bytes Non-null and exactly of {@link #REQUIRED_BYTE_LENGTH} length.  Assumed to be in MSB order as per Java's default
	 * @throws InvalidHeaderException If bytes didn't give magic that matched {@link #GENPMKMAGIC}.  Usually caused by
	 * 	using a file that isn't a hash database or a file that isn't in big endian (MSB) order.
	 * @throws IllegalArgumentException if bytes length is not equal to {@link #REQUIRED_BYTE_LENGTH}
	 * @throws NullPointerException if bytes is null
	 */
	public HashDatabaseHeader(final byte[] bytes) throws InvalidHeaderException {
		if(null == bytes) {
			throw new NullPointerException("bytes was null");
		}
		if(bytes.length != REQUIRED_BYTE_LENGTH) {
			throw new IllegalArgumentException("bytes length of " + bytes.length + " != " + REQUIRED_BYTE_LENGTH);
		}
		
		// Parse the magic
		ByteBuffer byteBuffer = ByteBuffer.wrap(bytes, 0, 4);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		long magic = SignedUnsignedNumberConvertor.unsignedIntToLong(byteBuffer.getInt());
		if(GENPMKMAGIC != magic) {
			throw new InvalidHeaderException("bytes gave magic value of " + Long.toString(magic) + " which wasn't expected of " + Long.toString(GENPMKMAGIC));
		}
		
		for(int i = 4; i <= 6; i++) {
			this.reserved[i - 4] = SignedUnsignedNumberConvertor.unsignedByteToInt(bytes[i]);
		}
		
		final int ssidLength = SignedUnsignedNumberConvertor.unsignedByteToInt(bytes[7]);
		
		if(ssidLength > MAXIMUM_SSID_LENGTH) {
			throw new InvalidHeaderException("SSID length of " + ssidLength + " is longer than specification allowed of " + MAXIMUM_SSID_LENGTH);
		}
		
		this.ssid = new String(bytes, 8, ssidLength, GlobalConstants.UTF8);
	}
	
	
	public int[] getReserved() {
		return reserved;
	}

	public String getSsid() {
		return ssid;
	}

	
	public class InvalidHeaderException extends Exception {
		private static final long serialVersionUID = 2685234817108563017L;
		
		public InvalidHeaderException(final String message) {
			super(message);
		}
	}
}
