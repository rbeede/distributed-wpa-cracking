package com.google.code.distributedwpacracking.master.servlets;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.WebAppConfig;
import com.google.code.distributedwpacracking.master.javabeans.HashDatabase;
import com.google.code.distributedwpacracking.master.utils.SSHRemoteCommand;
import com.jcraft.jsch.JSchException;

public class StartWorkerNodes extends HttpServlet {
	private static final long serialVersionUID = 4803957626429629436L;
	
	private static final Logger log = Logger.getLogger(StartWorkerNodes.class);
	
	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		log.info(req.getRemoteUser() + " has requested to start the worker node cluster");
		
		
		final InetSocketAddress[] addresses = WebAppConfig.getInstance().getWorkerNodes();
		
		final String startCmdTemplate = WebAppConfig.getInstance().getWorkerNodeStartCommand();
		
		final String sshUsername = WebAppConfig.getInstance().getWorkerNodeSshUsername();
		final String sshPrivateKey = WebAppConfig.getInstance().getWorkerNodeSshPrivateKeyFile();
		
		
		// We need to verify the rainbow table is valid
		final File rainbowTableDirectory = WebAppConfig.getInstance().getRainbowTableDirectory();
		if(null == rainbowTableDirectory) {
			final String errMsg = "ERROR:  No rainbow table is configured in the web application configuration.";
			log.fatal(errMsg);
			req.getSession().setAttribute("StatusMessage", errMsg);
			resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
			return;
		} else if(rainbowTableDirectory.listFiles() == null || rainbowTableDirectory.listFiles().length == 0) {
			final String errMsg = "No files in rainbow table directory " + rainbowTableDirectory.getAbsolutePath();
			log.error(errMsg);
			req.getSession().setAttribute("StatusMessage", errMsg);
			resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
			return;
		}
		// All SSID files in the directory must have the same byte size so offsets work
		File previousFile = rainbowTableDirectory.listFiles()[0];  // already checked that something is there
		for(final File ssidTableFile : rainbowTableDirectory.listFiles()) {
			if(previousFile.length() != ssidTableFile.length()) {
				final String errMsg = "Rainbow table file " + ssidTableFile.getName() + " has size "
					+ ssidTableFile.length() + " bytes which doesn't match previous table file " + previousFile.getName()
					+ " which has size " + previousFile.length() + " bytes.  Check your rainbow table directory in "
					+ rainbowTableDirectory.getAbsolutePath();
				log.error(errMsg);
				req.getSession().setAttribute("StatusMessage", errMsg);
				resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
				return;
			} else {
				previousFile = ssidTableFile;
			}
		}
		
		
		// We just need one file since we assume they are all the same byte size (verified) and that each one has
		//	the exact same dictionary and ordering
		
		// The easiest way is to just read the entire table for a single SSID into memory
		log.debug("Parsing rainbow table hash database from " + previousFile.getAbsolutePath());
		final HashDatabase rainbowTable;
		try {
			rainbowTable = new HashDatabase(previousFile);
		} catch(final Exception e) {  // Catches any RuntimeException for us too
			final String errMsg = "Could not parse rainbow table database:  " + e.getMessage();
			log.error(errMsg, e);
			req.getSession().setAttribute("StatusMessage", errMsg);
			resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
			return;
		}
		
		// Now we can use this information for calculating offsets later :) 
		// Figure out the rainbow table record ranges for this node
		final double blockSize = (double)rainbowTable.getRecords().size() / (double)addresses.length;  // must use (double) to preserve precision
		
		log.debug("Number of rainbow table records is " + rainbowTable.getRecords().size() + " which gives block sizes of "
				+ blockSize + " for " + addresses.length + " worker nodes");

		for(int i = 0; i < addresses.length; i++) {
			final InetSocketAddress address = addresses[i];
			
			log.info("Send start node to " + address.getHostName());
			
			String startCmd = startCmdTemplate.replace("${NODE_PORT}", Integer.toString(address.getPort()));
			startCmd = startCmd.replace("${NODES_COUNT}", Integer.toString(addresses.length));
			startCmd = startCmd.replace("${NODE_RANK}", Integer.toString(i));
			startCmd = startCmd.replace("${NODE_HOSTNAME}", address.getHostName());
			startCmd = startCmd.replace("${RAINBOW_TABLE_DIRECTORY}", rainbowTableDirectory.getAbsolutePath());
			startCmd = startCmd.replace("${NODE_RECORD_NUMBER}", Integer.toString(rainbowTable.getRecords().size()));
			
			final int startRange = (int) Math.ceil(blockSize * i);
			int endRange = (int) Math.floor((double)startRange + blockSize);
			
			if(addresses.length == (i+1) && (rainbowTable.getRecords().size() - 1 != endRange)) {
				// Need to pick up uneven division although it should be very close
				endRange = rainbowTable.getRecords().size() - 1;
			}
			
			log.debug(i + ":\t" + startRange + " to " + endRange);
			
			startCmd = startCmd.replace("${NODE_START_OFFSET}", Long.toString(rainbowTable.getRecords().get(startRange).getByteOffset()));
			startCmd = startCmd.replace("${NODE_END_OFFSET}", Long.toString(rainbowTable.getRecords().get(endRange).getByteOffset()));
			startCmd = startCmd.replace("${NODE_RECORD_START}", Integer.toString(startRange));
			startCmd = startCmd.replace("${NODE_RECORD_END}", Integer.toString(endRange));

			log.debug("startCmd:\t" + startCmd);
			
			try {
				SSHRemoteCommand.execBackground(address.getHostName(), sshUsername, sshPrivateKey, startCmd);
			} catch(final JSchException e) {
				log.error(address.toString() + "\t" + e.toString(), e);
				req.getSession().setAttribute("StatusMessage", "Error starting worker node on " + address.toString() + ".  " + e.toString());
				resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
				return;
			} catch(final InterruptedException e) {
				log.error(address.toString() + "\t" + e.toString(), e);
				req.getSession().setAttribute("StatusMessage", "Error starting worker node on " + address.toString() + ".  " + e.toString());
				resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
				return;
			}
			
			log.info(address.toString() + " ran start command in background");
		}
				
		req.getSession().setAttribute("StatusMessage", "Commands to start cluster were successful.  Update page to see node status.");
		resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
	}
}
