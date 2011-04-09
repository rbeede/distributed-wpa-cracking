package com.google.code.distributedwpacracking.master;

import java.nio.charset.Charset;

public class GlobalConstants {
	/**
	 * Including '\0' null pointer character at end
	 */
	public static final int TEXT_FIELD_MAX_LENGTH = 1024;
	/**
	 * Without the '\0'
	 */
	public static final int TEXT_FIELD_CHAR_MAX_LENGTH = TEXT_FIELD_MAX_LENGTH - 1;
	
	public static final int PACKET_MAX_LENGTH = 1024 * 4;
	
	public static final Charset UTF8 = Charset.forName("UTF-8");

}
