package com.google.code.distributedwpacracking.master;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.utils.StringUtils;

/**
 * @author Rodney Beede
 * 
 * Singleton using the enum method which also provides serialization and protects against reflection
 * See http://stackoverflow.com/questions/70689/efficient-way-to-implement-singleton-pattern-in-java
 * 
 * Access with WebAppConfig.INSTANCE or the traditional WebAppConfig.getInstance()
 *
 */
public enum WebAppConfig {
	INSTANCE;
	
	private static final Logger log = Logger.getLogger(WebAppConfig.class);
	
	private final Properties configProperties = new Properties();
	
	
	public static WebAppConfig getInstance() {
		return WebAppConfig.INSTANCE;
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
	
	/**
	 * Retrieves the value for any configuration property
	 * 
	 * @param name
	 * @return
	 */
	public String get(final String name) {
		return this.configProperties.getProperty(name);
	}
	
	
	public InetSocketAddress[] getWorkerNodes() {
		final String propValue = this.get("Worker Nodes");
		
		if(StringUtils.isEmpty(propValue)) {
			return null;
		}
		
		
		final String[] hostnamesAndPorts = propValue.split(",");
		
		final InetSocketAddress[] addresses = new InetSocketAddress[hostnamesAndPorts.length];
		
		for(int i = 0; i < hostnamesAndPorts.length; i++) {
			final String hostname = hostnamesAndPorts[i].substring(0, hostnamesAndPorts[i].lastIndexOf(':'));
			final int port = Integer.parseInt(hostnamesAndPorts[i].substring(hostnamesAndPorts[i].lastIndexOf(':')+1));
			
			addresses[i] = new InetSocketAddress(hostname, port);
		}
		
		return addresses;
	}
	
	
	public File getJobOutputDirectory() {
		final String propValue = this.get("Job Output Directory"); 
		
		if(StringUtils.isEmpty(propValue)) {
			return null;
		} else {
			return new File(propValue);
		}
	}
	
	
	public File getRainbowTableDirectory() {
		final String propValue = this.get("Rainbow Table Directory");
		
		if(StringUtils.isEmpty(propValue)) {
			return null;
		} else {
			return new File(propValue);
		}
	}
	
	
	public String getWorkerNodeStartCommand() {
		return this.get("Worker Node Start Command"); 
	}
	
	public String getWorkerNodeKillCommand() {
		return this.get("Worker Node Kill Command");
	}
	
	
	public String getWorkerNodeSshUsername() {
		return this.get("Worker Node SSH Username"); 
	}
	
	public String getWorkerNodeSshPrivateKeyFile() {
		return this.get("Worker Node SSH Private Key (no password) File"); 
	}
}
