package com.google.code.distributedwpacracking.master.exceptions;

public class InvalidRecordException extends Exception {
	private static final long serialVersionUID = -7973872958543122464L;

	public InvalidRecordException(final String message) {
		super(message);
	}
	
	public InvalidRecordException(final String message, final Throwable throwable) {
		super(message, throwable);
	}
}
