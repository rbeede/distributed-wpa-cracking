package com.google.code.distributedwpacracking.master.javabeans;

import com.google.code.distributedwpacracking.master.GlobalConstants;
import com.google.code.distributedwpacracking.master.exceptions.InvalidRecordException;
import com.google.code.distributedwpacracking.master.utils.SignedUnsignedNumberConvertor;


/**
 * @author rbeede
 *
 * This is a Java conversion of coWPAtty's cowpatty.h struct hashdb_rec as per coWPAtty version 4.6.
 * 
 * <p>
 * Endianness of bytes on disk should not affect reading into memory since struct uses 8-bit integers and a simple
 * array.  Same goes for the char array "word" which is null terminated.
 * </p>
 * 
 * <p>Assumes that "word" (password) is encoded with {@value GlobalConstants#UTF8}
 * 
 * <p>
 * Note that the struct was define as follows:<br />
 * <pre>
		struct hashdb_rec {
			uint8_t rec_size;
			char *word;
			uint8_t pmk[32];
		} __attribute__ ((packed));
 * </pre>
 * </p>
 * 
 * <p>"__attribute__ ((packed))" means that the bytes are not padded per a gcc extension.</p>
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
 *
 */
public class HashDatabaseRecord {
	/**
	 * IEEE Std 802.11-2007
	 * H.4 Suggested pass-phrase-to-PSK mapping
	 * Page 1129
	 */
	public static final int MAXIMUM_PASSWORD_LENGTH = 63;
	
	public static final int MINIMUM_BYTE_LENGTH = 1 + 0 + 1*32;
	public static final int MAXIMUM_BYTE_LENGTH = MINIMUM_BYTE_LENGTH + MAXIMUM_PASSWORD_LENGTH;
	
	
	private final int recordSize;
	private final String password;
	private final byte[] pairwiseMasterKey = new byte[32];
	
	private final long byteOffset;  // Where in the underlying file is this record?
	
	/**
	 * @param bytes Non-null and at least {@link #MINIMUM_BYTE_LENGTH} length but no more than MINIMUM_BYTE_LENGTH
	 * @throws InvalidRecordException Record size parsed from bytes didn't match bytes length
	 * @throws IllegalArgumentException if bytes.length < MINIMUM_BYTE_LENGTH or bytes.length > MAXIMUM_BYTE_LENGTH
	 */
	public HashDatabaseRecord(final byte[] bytes, final long byteOffset) throws InvalidRecordException {
		if(null == bytes) {
			throw new NullPointerException("bytes was null");
		}
		if(bytes.length < MINIMUM_BYTE_LENGTH) {
			throw new IllegalArgumentException("bytes length of " + bytes.length + " < " + MINIMUM_BYTE_LENGTH);
		} else if(bytes.length > MAXIMUM_BYTE_LENGTH) {
			throw new IllegalArgumentException("bytes length of " + bytes.length + " > " + MAXIMUM_BYTE_LENGTH);
		}
		
		this.recordSize = SignedUnsignedNumberConvertor.unsignedByteToInt(bytes[0]);
		
		if(bytes.length != this.recordSize) {
			throw new InvalidRecordException("record size parsed was " + this.recordSize + " but bytes.length was " + bytes.length);
		}
		
		final int passwordLength = this.recordSize - (pairwiseMasterKey.length + 1);  // + 1 is "uint8_t rec_size"
		
		this.password = new String(bytes, 1, passwordLength, GlobalConstants.UTF8);
		
		assert this.password.length() == passwordLength;
		
		for(int i = 1 + passwordLength; i < bytes.length; i++) {
			this.pairwiseMasterKey[i - (1 + passwordLength)] = bytes[i];
		}
		
		this.byteOffset = byteOffset;
	}
	
	public int getRecordSize() {
		return recordSize;
	}
	
	public String getPassword() {
		return password;
	}
	
	public byte[] getPairwiseMasterKey() {
		return pairwiseMasterKey;
	}
	
	/**
	 * @return Where in the underlying hash database file this record starts (header included)
	 */
	public long getByteOffset() {
		return byteOffset;
	}
}
