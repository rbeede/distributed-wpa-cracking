package com.google.code.distributedwpacracking.master.javabeans;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.google.code.distributedwpacracking.master.exceptions.InvalidRecordException;
import com.google.code.distributedwpacracking.master.javabeans.HashDatabaseHeader.InvalidHeaderException;

public class HashDatabase {
	private final File file;
	private final HashDatabaseHeader header;
	/**
	 * Set to unmodifiable List via Collections.unmodifiableList
	 */
	private final List<HashDatabaseRecord> records;
	
	public HashDatabase(final File file) throws IOException, InvalidHeaderException, InvalidRecordException {
		this.file = file;
		
		final FileInputStream fis = new FileInputStream(this.file);
		
		byte[] buffer = new byte[HashDatabaseHeader.REQUIRED_BYTE_LENGTH];
		fis.read(buffer);
		
		this.header = new HashDatabaseHeader(buffer);
		
		this.records = parseRecords(fis);
		
		fis.close();
	}
	
	public File getFile() {
		return this.file;
	}
	
	public HashDatabaseHeader getHeader() {
		return this.header;
	}
	
	/**
	 * @return Unmodifiable list of records
	 */
	public List<HashDatabaseRecord> getRecords() {
		return this.records;
	}
	
	/**
	 * @param fis Must already be at byte of first record.  Not closed.
	 * @return Unmodifiable list of records
	 * @throws IOException 
	 * @throws InvalidRecordException 
	 */
	private List<HashDatabaseRecord> parseRecords(final FileInputStream fis) throws IOException, InvalidRecordException {
		final List<HashDatabaseRecord> parsedRecords = new ArrayList<HashDatabaseRecord>();
		
		
		// Read the current record size (1 byte -> uint8 or an unsigned 8-bit integer)
		while(true) {
			// Where this record starts in the file
			long byteOffset = fis.getChannel().position();  // first time this will be next byte after header
			
			final int recordSize = fis.read();  // integer will already be value from 0 to 255 (unsigned byte or unsigned 8-bit int)
			if(-1 == recordSize) {
				// Done
				break;
			}
			
			final byte[] buffer = new byte[recordSize];  // if recordSize is too big will get caught in HashDatabaseRecord constructor later
			buffer[0] = (byte) recordSize;  // back to Java signed byte to be adjusted later in HashDatabaseRecord constructor
			final int bytesRead = fis.read(buffer, 1, recordSize - 1);  // We've already read 1 byte
			if(bytesRead != recordSize - 1) {
				throw new IOException("record size of " + recordSize + " was in file, but only read " + bytesRead
						+ " actual bytes!  Number of correctly parsed records before this error was " + parsedRecords.size());
			}
			
			final HashDatabaseRecord parsedRecord;
			try {
				parsedRecord = new HashDatabaseRecord(buffer, byteOffset);
			} catch(final InvalidRecordException e) {
				throw new InvalidRecordException("at record number " + (parsedRecords.size() + 1) + " and byte offset " + byteOffset + ":  " + e.getMessage(), e);
			}
			parsedRecords.add(parsedRecord);
		}
		
		
		return Collections.unmodifiableList(parsedRecords);
	}
}
