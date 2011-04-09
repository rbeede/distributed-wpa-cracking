package com.google.code.distributedwpacracking.master.utils;

/**
 * @author rbeede
 * 
 * Java's internal storage of numbers are as signed numbers.  This class takes a Java number and treats it as either
 * unsigned or signed and converts it to the specified Java number.
 *
 */
public class SignedUnsignedNumberConvertor {
	/**
	 * Treat the Java signed byte b as if it were really unsigned and return it as an integer.
	 * 
	 * @param b
	 * @return
	 */
	public static int unsignedByteToInt(final byte b) {
		// 1.  Convert the signed byte "b" to a signed int
		// 2.  Since a byte is 8-bits we drop the sign bits that are extra in the int
		return (int) b & 0xFF;  // FF keeps 8 bits to far right, anything to left is just like 0x00FF and made to zero
	}
	
	/**
	 * Treat the Java signed int value as if it were really unsigned and return it as an long.
	 * 
	 * @param b
	 * @return
	 */
	public static long unsignedIntToLong(final int value) {
		// 1.  Convert the signed byte "b" to a signed long
		//		Value now has Long.SIZE bits (64 bits)
		// 2.  Since a byte is 8-bits we drop the sign bits that are extra in the long
		return (long) value & 0xFFFFFFFF;  // FF keeps 32 bits to far right, anything to left is zeroed out
	}
}
