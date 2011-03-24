package com.google.code.distributedwpacracking.master.utils;

public class StringUtils {
	public static boolean isEmpty(final String string) {
		if(null == string) {
			return true;
		} else {
			return string.isEmpty();
		}
	}
	
	public static String join(final String separator, final Object[] items) {
		if(null == items || items.length == 0) {
			return "";
		}
		
		final StringBuilder sb = new StringBuilder();
		
		for(int i = 0; i < items.length - 1; i++) {
			sb.append(items[i].toString());
			sb.append(separator);
		}
		sb.append(items[items.length - 1]);
		
		return sb.toString();
	}
	
	public static String replaceAll(final String string, final String regex, final String replacement) {
		if(StringUtils.isEmpty(string))  return string;
		
		return string.replaceAll(regex, replacement);
	}
}
