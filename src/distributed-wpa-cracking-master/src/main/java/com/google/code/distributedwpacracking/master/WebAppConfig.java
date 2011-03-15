package com.google.code.distributedwpacracking.master;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;

public class WebAppConfig {
	private static final WebAppConfig _instance = new WebAppConfig();
	
	private static final Logger log = Logger.getLogger(WebAppConfig.class);
	
	private final Properties configProperties = new Properties();
	
	private WebAppConfig() {
	}
	
	public static WebAppConfig getInstance() {
		return _instance;
	}
	
	public Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException(); 
	}
	
	/**
	 * Dumps any existing configuration and loads the configuration from the given file.  If file I/O fails configuration will be blank.
	 * 
	 * @param file File to load which should be an xml formatted properties format
	 * @throws IOException If any errors occur while reading the file or if the file is corrupt
	 */
	public void loadConfig(final File file) throws IOException {
		this.configProperties.clear();
		
		try {
			this.configProperties.loadFromXML(new FileInputStream(file));
		} catch(final IOException e) {
			log.error(e,e);
			this.configProperties.clear();  // Empty on error
			throw e;
		}
		
		log.debug("Config settings are now " + this.configProperties.toString());
	}
	
	public String get(final String name) {
		return this.configProperties.getProperty(name);
	}
}
