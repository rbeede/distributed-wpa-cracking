package com.google.code.distributedwpacracking.master.servlets;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.log4j.Logger;

public class InitializationServlet implements ServletContextListener {
	private static final Logger log = Logger.getLogger(InitializationServlet.class);
	
	@Override
	public void contextInitialized(final ServletContextEvent sce) {
		log.debug("Application is starting");
		
	}
}
