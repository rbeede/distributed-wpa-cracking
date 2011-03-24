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
		
		//FIXME Use threading to report back status via Callable so all ssh commands start at once
		for(int i = 0; i < addresses.length; i++) {
			final InetSocketAddress address = addresses[i];
			String startCmd = startCmdTemplate.replace("${NODE_PORT}", Integer.toString(address.getPort()));
			startCmd = startCmd.replace("${NODES_COUNT}", Integer.toString(addresses.length));
			startCmd = startCmd.replace("${NODE_RANK}", Integer.toString(i+1));

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
