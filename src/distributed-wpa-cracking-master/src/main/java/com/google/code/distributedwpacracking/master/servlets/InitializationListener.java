package com.google.code.distributedwpacracking.master.servlets;

import java.io.File;
import java.io.IOException;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.WebAppConfig;

public class InitializationListener implements ServletContextListener {
	private static final Logger log = Logger.getLogger(InitializationListener.class);
	
	@Override
	public void contextInitialized(final ServletContextEvent sce) {
		// Print to STDOUT (usually winds up in some web app container log file) where we are loggin
		final org.apache.log4j.rolling.RollingFileAppender rollingAppender = (org.apache.log4j.rolling.RollingFileAppender) Logger.getRootLogger().getAppender("rolling");
		if(null != rollingAppender) {
			System.out.println(sce.getServletContext().getContextPath() + " is logging to rolling file at " + rollingAppender.getFile());
		}
		
		
		log.debug("Application is starting");
		
		final File configFile = new File(sce.getServletContext().getInitParameter("WebAppConfig.xml Full Pathname"));
		log.info("Using configuration at " + configFile.getAbsolutePath());
		
		try {
			WebAppConfig.getInstance().loadConfig(configFile);
		} catch(final IOException e) {
			log.fatal(e,e);
			throw new RuntimeException(e.getMessage(),e);  // kills app from being loaded
		}
		
		
		
	}

	@Override
	public void contextDestroyed(final ServletContextEvent sce) {
		log.debug("Application is shutting down");
	}
}
