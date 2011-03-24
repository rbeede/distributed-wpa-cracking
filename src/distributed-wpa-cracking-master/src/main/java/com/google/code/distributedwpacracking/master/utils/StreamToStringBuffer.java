package com.google.code.distributedwpacracking.master.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

import org.apache.commons.io.IOUtils;

/**
 * @author Rodney
 * 
 * Assumes UTF-8.
 * 
 * Any errors result in the termination of reading.
 *
 */
public class StreamToStringBuffer extends Thread {
	private final InputStream is;
	private final StringBuffer sb;
	
	/**
	 * Reads content from is until end of stream is reached and writes it to sb.  Assumes UTF-8.
	 * 
	 * @param is If null nothing is done.
	 * @param sb If null content is read from is until empty but saved nowhere.
	 */
	public StreamToStringBuffer(final InputStream is, final StringBuffer sb) {
		this.is = is;
		this.sb = sb;
	}
	
	@Override
	public void run() {
		if(null == is)  return;
		
		InputStreamReader isr;
		try {
			isr = new InputStreamReader(this.is, "UTF-8");
		} catch (final UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage(),e);  // If system can't support encoding then hopeless
		}
		
		final char[] buffer = new char[1024 * 4];
		
		int bytesRead;
		try {
			while(-1 != (bytesRead = isr.read(buffer))) {
				if(null != this.sb) {
					sb.append(buffer, 0, bytesRead);
				}
			}
		} catch (final IOException e) {
			// Just fall through to close statements
		}
		
		IOUtils.closeQuietly(isr);
		
		IOUtils.closeQuietly(this.is);
	}
}
