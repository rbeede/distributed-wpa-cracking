package com.google.code.distributedwpacracking.master.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.GlobalConstants;
import com.google.code.distributedwpacracking.master.Job;
import com.google.code.distributedwpacracking.master.WebAppConfig;

public class WorkerNodeManager {
	private static final Logger log = Logger.getLogger(WorkerNodeManager.class);
	
	private static final int SOCKET_CONNECT_TIMEOUT_MILLISECONDS = 800;
	private static final int SOCKET_IO_TIMEOUT_MILLISECONDS = SOCKET_CONNECT_TIMEOUT_MILLISECONDS * 3;
	
	private final InetSocketAddress[] addresses;
	
	public WorkerNodeManager(final InetSocketAddress[] addresses) {
		this.addresses = addresses;
	}
	
	public String[] getWorkerNodeStatus() {
		final String[] statusReports = new String[this.addresses.length];
		
		for(int i = 0; i < this.addresses.length; i++) {
			final InetSocketAddress address = this.addresses[i];
			
			final String[] responseParts = queryStatus(address);
			
			statusReports[i] = address.toString();
			statusReports[i] += " ";
			statusReports[i] += StringUtils.join(" ", responseParts);
		}
		
		return statusReports;
	}
	
	
	public String[] submitJob(final Job job) {
		final String[] statusReports = new String[this.addresses.length];
		
		
		final File jobDir = new File(WebAppConfig.getInstance().getJobOutputDirectory(), job.getId());
		final File captureFile = new File(jobDir, "WIRELESS_CAPTURE");
		
		for(int i = 0; i < this.addresses.length; i++) {
			final InetSocketAddress address = this.addresses[i];
			
			final String[] responseParts;
			try {
				responseParts = commWorker(address, "START", job.getId(), captureFile.getAbsolutePath(), jobDir.getAbsolutePath(), job.getSsid());
			} catch(final IOException e) {
				final String errMsg = "Job id of " + job.getId() + " failed to submit to worker node with error " + e.getMessage();
				log.error(errMsg, e);
				statusReports[i] = address + " ERROR " + errMsg;
				continue;
			}
			
			statusReports[i] = address.toString();
			statusReports[i] += " ";
			statusReports[i] += StringUtils.join(" ", responseParts);
		}
		
		return statusReports;
	}
	
	
	/**
	 * May attempt to kill job that reached FINISHED on worker node.  Worker node will ignore this and just return an error.
	 * 
	 * We don't really care about the error all that much.  We just log the returned status code for debugging.
	 * 
	 * It is really a blind kill signal without verification that worker nodes went back to ready state.
	 * 
	 * @param job
	 * @return
	 */
	public String[] killJob(final Job job) {
		final String[] statusReports = new String[this.addresses.length];
		
		
		for(int i = 0; i < this.addresses.length; i++) {
			final InetSocketAddress address = this.addresses[i];
			
			final String[] responseParts;
			try {
				responseParts = commWorker(address, "KILLJOB", job.getId());
			} catch(final IOException e) {
				final String errMsg = "Job id of " + job.getId() + " failed to submit to worker node with error " + e.getMessage();
				log.error(errMsg, e);
				statusReports[i] = address.toString() + " ERROR " + errMsg;
				continue;
			}
			
			statusReports[i] = address.toString();
			statusReports[i] += " ";
			statusReports[i] += StringUtils.join(" ", responseParts);
		}
		
		return statusReports;
	}
	
	
	private String[] commWorker(final InetSocketAddress address, final String... requestParts) throws IOException {
		log.trace(address.toString() + "\t" + StringUtils.join(" ", requestParts));
		
		final Socket socket = new Socket();
		
		try {
			socket.setSoTimeout(SOCKET_IO_TIMEOUT_MILLISECONDS);
		} catch (final SocketException e) {
			log.fatal(e,e);  // OS problem
			throw e;
		}

		
		// Size check
		int packetByteCount = 0;
		for(final String requestPart : requestParts) {
			if(requestPart.length() > GlobalConstants.TEXT_FIELD_CHAR_MAX_LENGTH) {
				final String errMsg = "Request part has length " + requestPart.length() + " which exceeds " + GlobalConstants.TEXT_FIELD_CHAR_MAX_LENGTH;
				log.fatal(errMsg);
				throw new IOException(errMsg);
			}
			
			packetByteCount += requestPart.length() + 1;  // +1 for the null char
			packetByteCount += 1;  // Unit Separator
		}
		packetByteCount++;  // End of Transmission
		if(packetByteCount > GlobalConstants.PACKET_MAX_LENGTH) {
			final String errMsg = "Packet has length " + packetByteCount + " which exceeds " + GlobalConstants.PACKET_MAX_LENGTH;
			log.fatal(errMsg);
			throw new IOException(errMsg);
		}
		
		
		socket.connect(address, SOCKET_CONNECT_TIMEOUT_MILLISECONDS);

		final OutputStream os = socket.getOutputStream();
		
		for(final String requestPart : requestParts) {
			os.write(requestPart.getBytes(GlobalConstants.UTF8));
			os.write(0);  // null terminator
			os.write(31);  // US ASCII Unit Separator
		}
		os.write(4);  // US ASCII End of Transmission
		
		// Don't close the OutputStream or the entire socket gets closed
		
		socket.shutdownOutput();  // half-way shutdown
		
		
		// Read the response
		final InputStream is = socket.getInputStream();
		
		final byte[] buffer = new byte[GlobalConstants.PACKET_MAX_LENGTH];
		int bufferBytesRead = 0;
		int totalBytesRead = 0;
		while(-1 != (bufferBytesRead = is.read(buffer, totalBytesRead, buffer.length - totalBytesRead))) {
			totalBytesRead += bufferBytesRead;
			
			if(buffer.length == totalBytesRead) {
				break;  // Read maximum possible so may be invalid
			}
		}
		
		// Don't close the InputStream as that closes the entire socket
		
		
		socket.close();  // Really close everything now
		
		
		final Collection<String> responseParts = new ArrayList<String>();
		int offset = 0;
		for(int i = 0; i < buffer.length; i++) {
			if((char) 31 == buffer[i]) {
				// part should include '\0' from buffer, but if buffer is incorrect Java still handles the string termination
				String part = new String(buffer, offset, i - offset, GlobalConstants.UTF8);
				
				// Strip out any control chars or \0 since we don't want those displayed
				part = part.replace("\0", "");
				part = part.replace("\4", "");
				
				responseParts.add(part);
				
				offset = i + 1;
			} else if('\4' == buffer[i]) {
				offset = i;  // so we can check later
				break;
			}
		}
		
		// Sanity check on packet well-formedness
		if(offset >= buffer.length || '\4' != buffer[offset]) {
			// Packet didn't have End of Transmission in it so invalid or remote responded with packet too long
			final IOException excep = new IOException("Packet did not contain EoT marker!  offset reached was " + offset);
			log.error(excep,excep);
			throw excep;
		}
		
		return responseParts.toArray(new String[responseParts.size()]);
	}
	
	
	private String[] queryStatus(final InetSocketAddress address) {
		try {
			return commWorker(address, "STATUS");
		} catch (final IOException e) {
			log.trace(e,e);
			return new String[] {"NOT LOADED", e.toString()};
		}
	}
}
