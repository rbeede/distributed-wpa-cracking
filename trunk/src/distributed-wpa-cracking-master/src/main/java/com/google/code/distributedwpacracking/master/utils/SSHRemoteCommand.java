package com.google.code.distributedwpacracking.master.utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

public class SSHRemoteCommand {
	private static final Logger log = Logger.getLogger(SSHRemoteCommand.class);
	
	/**
	 * @param hostname
	 * @param username
	 * @param privateKeyFilePath
	 * @param command
	 * @return Array where element 0 is STDOUT from remote process and 1 is STDERR and 2 is the string form of the exit code
	 * @throws IOException 
	 * @throws JSchException 
	 * @throws InterruptedException 
	 */
	public static StringBuffer[] exec(final String hostname, final String username, final String privateKeyFilePath, final String command) throws JSchException, IOException, InterruptedException {
		final StringBuffer[] commandOutput = new StringBuffer[3];
		
		
		final JSch jsch = new JSch();
		
		// known_hosts just like openssh does it
		jsch.setKnownHosts(combinedKnownHosts("/etc/ssh/ssh_known_hosts", System.getProperty("user.home") + "/.ssh/known_hosts"));
		
		// Add our private key for public key auth
		jsch.addIdentity(privateKeyFilePath);
		
		log.debug("Using private key " + privateKeyFilePath + " to connect to " + hostname + " as user " + username);
		
		final Session session = jsch.getSession(username, hostname);
		
		session.connect(1000);  // 1 second timeout
		
		final ChannelExec channel = (ChannelExec) session.openChannel("exec");
	    channel.setCommand(command);
	      
	    
	    // We must setup the input and output channels for the ssh command or it could hang forever
	    
	    channel.setInputStream(null);  // STDIN for remote command is nothing
	      
	    // The Jsch API is really confusing here on streams and which is which
	    final InputStream cmdStdout = channel.getInputStream();		// remote processes STDOUT
	    final InputStream cmdStderr = channel.getErrStream();		// remote processes STDERR
	      
	    log.debug("Executing command " + command);
	    channel.connect();
	    
	    
	    // Setup reader threads to capture output
	    commandOutput[0] = new StringBuffer();
	    commandOutput[1] = new StringBuffer();
	    final Thread stdoutThread = new StreamToStringBuffer(cmdStdout, commandOutput[0]);
	    final Thread stderrThread = new StreamToStringBuffer(cmdStderr, commandOutput[1]);
	    
	    stdoutThread.start();
	    stderrThread.start();
	    stdoutThread.join();
	    stderrThread.join();
	    
	    while(!channel.isClosed()) {
	    	try {
				Thread.sleep(500);
			} catch (final InterruptedException e) {
				break;
			}
	    }
	   
	    commandOutput[2] = new StringBuffer();
	    commandOutput[2].append(channel.getExitStatus());

		channel.disconnect();
		session.disconnect();
		
		for(final StringBuffer sb : commandOutput) {
			log.debug(sb.toString());
		}
		
		return commandOutput;
	}
	
	
	/**
	 * STDIN, STDOUT, and STDERR are set to null.
	 * 
	 * @param hostname
	 * @param username
	 * @param privateKeyFilePath
	 * @param command Command to run in background.  The " &" will be added for you.
	 * @throws JSchException
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void execBackground(final String hostname, final String username, final String privateKeyFilePath, final String command) throws JSchException, IOException, InterruptedException {
		final JSch jsch = new JSch();
		
		// known_hosts just like openssh does it
		jsch.setKnownHosts(combinedKnownHosts("/etc/ssh/ssh_known_hosts", System.getProperty("user.home") + "/.ssh/known_hosts"));
		
		// Add our private key for public key auth
		jsch.addIdentity(privateKeyFilePath);
		
		log.debug("Using private key " + privateKeyFilePath + " to connect to " + hostname + " as user " + username);
		
		final Session session = jsch.getSession(username, hostname);
		
		session.connect(1000);  // 1 second timeout
		
		final ChannelExec channel = (ChannelExec) session.openChannel("exec");
	    channel.setCommand(command + " &");
	      
	    
	    // We must setup the input and output channels for the ssh command or it could hang forever
	    
	    channel.setInputStream(null);  // STDIN for remote command is nothing
	      
	    // The Jsch API is really confusing here on streams and which is which
	    channel.setOutputStream(null);		// remote processes STDOUT
	    channel.setErrStream(null);			// remote processes STDERR
	      
	    log.debug("Executing background command " + command + " &");
	    channel.connect();
	    
	    
	    channel.disconnect();
		session.disconnect();
	}
	
	
	private static InputStream combinedKnownHosts(final String... known_hostsPaths) throws IOException {
		long neededBufferSize = 0;
		
		final Collection<File> existingFiles = new ArrayList<File>(known_hostsPaths.length);
		
		for(final String filePath : known_hostsPaths) {
			final File file = new File(filePath);
			if(file.exists()) {
				neededBufferSize += file.length();
				neededBufferSize++;  // includes the '\n' we have to insert
				existingFiles.add(file);
				
				log.debug("known_hosts Exists:  " + file.getAbsolutePath());
			} else if(log.isDebugEnabled()) {
				log.debug("known_hosts Non-Existant:  " + file.getAbsolutePath());
			}
		}
		
		if(neededBufferSize > Integer.MAX_VALUE) {
			// Java can't handle a single byte array this big
			throw new IOException("Combined file size of " + neededBufferSize + " is too large to hold in an array in memory");
		}
		
		final byte[] buffer = new byte[(int) neededBufferSize];
		
		int offset = 0;
		for(final File file : existingFiles) {
			final BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
			
			int totalBytesRead = 0;	// just for this file
			int bytesRead = -1;		// just for this file
			while(totalBytesRead != file.length()) {
				bytesRead = bis.read(buffer, offset, (int) file.length() - totalBytesRead);
				
				assert -1 != bytesRead;
				
				totalBytesRead += bytesRead;
				offset += bytesRead;
			}
			bis.close();

			// We need a separator between each file so the last and first lines of files don't get mixed on the same line
			buffer[offset] = '\n';
			offset++;
		}
		
		assert offset == buffer.length;  // should be past end when all is done
		
		return new ByteArrayInputStream(buffer);
	}
}
