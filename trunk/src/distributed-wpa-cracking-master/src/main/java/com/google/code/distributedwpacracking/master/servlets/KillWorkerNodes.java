package com.google.code.distributedwpacracking.master.servlets;

import java.io.IOException;
import java.net.InetSocketAddress;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.WebAppConfig;
import com.google.code.distributedwpacracking.master.utils.SSHRemoteCommand;
import com.jcraft.jsch.JSchException;

public class KillWorkerNodes extends HttpServlet {
	private static final long serialVersionUID = 2266400912780502732L;
	
	private static final Logger log = Logger.getLogger(KillWorkerNodes.class);
	
	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		log.info(req.getRemoteUser() + " has requested to kill the worker node cluster");
		
		
		final InetSocketAddress[] addresses = WebAppConfig.getInstance().getWorkerNodes();
		
		final String cmd = WebAppConfig.getInstance().getWorkerNodeKillCommand();
		
		final String sshUsername = WebAppConfig.getInstance().getWorkerNodeSshUsername();
		final String sshPrivateKey = WebAppConfig.getInstance().getWorkerNodeSshPrivateKeyFile();
		
		final StringBuffer sbResponseText = new StringBuffer();
		
		//FIXME Use threading to report back status via Callable so all ssh commands start at once
		for(int i = 0; i < addresses.length; i++) {
			final InetSocketAddress address = addresses[i];

			final StringBuffer[] cmdOutput;
			try {
				cmdOutput = SSHRemoteCommand.exec(address.getHostName(), sshUsername, sshPrivateKey, cmd);
			} catch(final JSchException e) {
				log.error(address.toString() + "\t" + e.toString(), e);
				req.getSession().setAttribute("StatusMessage", "Error with ssh to worker node on " + address.toString() + ".  " + e.toString());
				resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
				return;
			} catch(final InterruptedException e) {
				log.error(address.toString() + "\t" + e.toString(), e);
				req.getSession().setAttribute("StatusMessage", "Error with ssh to worker node on " + address.toString() + ".  " + e.toString());
				resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
				return;
			}
			
			if(null == cmdOutput || 3 != cmdOutput.length) {
				log.error("No valid cmdOutput for " + address.toString() + "\t" + cmd);
				resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "cmdOutput came back unknown");
				return;
			} else if(!cmdOutput[2].equals("0")) {
				// Error occurred
				log.warn(cmd + " for " + address.toString());
				log.warn("STDOUT for " + address.toString());
				log.warn(cmdOutput[0]);
				log.warn("STDERR for " + address.toString());
				log.warn(cmdOutput[1]);
				log.warn("ExitCode for " + address.toString() + " was " + cmdOutput[2]);
				
				// Might have tried to kill something that wasn't running anyway
				sbResponseText.append(address.toString());
				sbResponseText.append(cmdOutput[0]);
				sbResponseText.append(cmdOutput[1]);
				sbResponseText.append(cmdOutput[2]);
				sbResponseText.append("\n\t");
			} else {
				log.info(address.toString() + " ran kill command with success");
			}
		}
				
		req.getSession().setAttribute("StatusMessage", "Kill command sent.  Command responses:  " + sbResponseText.toString());
		resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
	}
}
