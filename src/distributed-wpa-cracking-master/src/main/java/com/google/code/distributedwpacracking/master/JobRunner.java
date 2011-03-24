package com.google.code.distributedwpacracking.master;

import org.apache.log4j.Logger;

public class JobRunner implements Runnable {
	private static final Logger log = Logger.getLogger(JobRunner.class);
	
	private static final int POLL_INTERVAL_MILLISECONDS = 5 * 1000;

	@Override
	public void run() {
		log.info("Waiting on jobs to be queued");
		
		while(true) {
			final Job currJob;
			try {
				currJob = GlobalData.getInstance().getJobQueue().take();
			} catch(final InterruptedException e) {
				log.debug("Looks like app is shutting down:  " + e.getMessage(),e);  // Most likely due to shutdown of app
				return;
			}
			
			
			// Make sure the cluster is up
			while(!clusterIsReady()) {
				try {
					Thread.sleep(POLL_INTERVAL_MILLISECONDS);
				} catch (final InterruptedException e) {
					log.debug("Looks like app is shutting down:  " + e.getMessage(),e);  // Most likely due to shutdown of app
					return;
				}
			}
			
			
			log.info("Starting job owned by " + currJob.getOwner() + " with id " + currJob.getId() + " and cluster reports it is ready");
			
		
			try {
				currJob.run();
			} catch(final Throwable t) {
				log.error(t,t);
				// Job itself should have updated its own status and recorded errors in the log too
			}
			
			log.debug("Finished with job owned by " + currJob.getOwner() + " with id " + currJob.getId());
		}

	}
	
	
	private boolean clusterIsReady() {
		final String[] clusterStatus = GlobalData.getInstance().getWorkerNodeManager().getWorkerNodeStatus();
		
		for(final String workerNodeStatus : clusterStatus) {
			if(workerNodeStatus.contains("RUNNING") || workerNodeStatus.contains("NOT LOADED") || workerNodeStatus.contains("ERROR")) {
				return false;
			}
		}
		
		
		return true;
	}

}
