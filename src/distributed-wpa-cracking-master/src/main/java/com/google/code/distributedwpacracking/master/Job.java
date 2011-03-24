package com.google.code.distributedwpacracking.master;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Calendar;

import org.apache.log4j.Logger;


public class Job implements Runnable {
	private static final Logger log = Logger.getLogger(Job.class);
	
	private static final int POLL_INTERVAL_MILLISECONDS = 5 * 1000;
	
	public enum JobState {
		NotRan,
		Running,
		Completed,
		Cancelled,
		Error,
	}
	
	private JobState state = JobState.NotRan;
	private Calendar startTime;
	private Calendar endTime;
	private String result;
	
	private final String owner;
	private final Calendar submissionTime;
	private final String id;
	private final String ssid;

	
	public Job(final String owner, final String ssid) {
		this.owner = (null != owner) ? owner : "anonymous";
		this.ssid = ssid;
		
		this.submissionTime = Calendar.getInstance();
		this.id = generateId(this.owner);
	}

	@Override
	public void run() {
		if(JobState.Cancelled.equals(this.state)) {
			// Ignore run
			log.info("Ignoring cancelled job " + this.id);
			return;
		} else if(!JobState.NotRan.equals(this.state)) {
			throw new IllegalStateException("Cannot run job again when it is in the " + this.state + " state.  Can only run when in " + JobState.NotRan.toString() + " state");
		} else {
			this.setState(JobState.Running);
		}

		
		this.startTime = Calendar.getInstance();
		log.info("Job " + this.getId() + " is starting");

		
		// Cluster should already be prepared as checked by JobRunner
		// Unless it just went down of course, if so this job will fail
		
		// Send all the nodes the job to run
		final String[] startNodeResponses = GlobalData.getInstance().getWorkerNodeManager().submitJob(this);
		
		// Check that the nodes accepted the job
		for(final String response : startNodeResponses) {
			if(response.contains("ERROR")) {
				this.setState(JobState.Error);
				log.error(response);
				this.result = response;
				return;
			}
		}
		
		
		// Query periodically the current job state
		while(!JobState.Cancelled.equals(this.state)) {
			final String[] jobNodeStates = GlobalData.getInstance().getWorkerNodeManager().getWorkerNodeStatus();
			
			int numFinished = 0;
			for(final String state : jobNodeStates) {
				if(state.contains("FINISHED")) {
					numFinished++;
				} else if(state.contains("ERROR")) {
					this.setState(JobState.Error);
					log.error(state);
					this.result = state;
					return;
				}
			}
			
			// Have we already found the answer even if all are not finished?
			if(solutionExists()) {
				log.info("Solution found for job id " + this.getId());
				
				// Kill any others that were still working
				final String[] nodeResponses = GlobalData.getInstance().getWorkerNodeManager().killJob(this);
				for(final String response : nodeResponses) {
					log.debug(response);
				}
				
				// Read in the result
				try {
					this.result = readSolution();
				} catch (final IOException e) {
					final String errMsg = "Solution found but could not read because:  " + e.toString();
					
					log.error(errMsg, e);
					this.result = errMsg;
					this.setState(JobState.Error);
					return;
				}
				
				break;
			}
			
			// Have all worker nodes finished searching with no result?
			if(numFinished == jobNodeStates.length) {
				this.result = "No Solution Found";
				break;
			}
			
			
			// Nodes are still working at it
			try {
				Thread.sleep(POLL_INTERVAL_MILLISECONDS);
			} catch (final InterruptedException e) {
				log.debug("Looks like app is shutting down:  " + e.getMessage(),e);  // Most likely due to shutdown of app
				this.setState(JobState.Error);
				this.result = e.toString();
				return;
			}
		}

		
		log.info("Job id " + this.getId() + " has a result of " + this.result);
		
		this.endTime = Calendar.getInstance();
		this.setState(JobState.Completed);
	}
	
	private boolean solutionExists() {
		final File jobDir = new File(WebAppConfig.getInstance().getJobOutputDirectory(), this.getId());
		final File solutionFile = new File(jobDir, "SOLUTION");
		
		return solutionFile.exists();
	}
	
	private String readSolution() throws IOException {
		final File jobDir = new File(WebAppConfig.getInstance().getJobOutputDirectory(), this.getId());
		final File solutionFile = new File(jobDir, "SOLUTION");

		final BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(solutionFile), "UTF-8"));
		final String solution = br.readLine();
		br.close();
		
		return solution;
	}
	
	
	/**
	 * Sets state to {@link JobState#Cancelled} iff not in state {@link JobState#Completed}.
	 * 
	 * <p>Calling multiple times has no effect.</p>
	 * 
	 * <p>If currently running may not immediately interrupt the operation or may still reach Completed state.</p>
	 * 
	 * <p>If an attempt to run after cancel then ignores run.</p>
	 */
	public void cancel() {
		synchronized (this.state) {
			if(JobState.Completed.equals(this.state)) {
				return;  // Nothing to update
			} else {
				this.state = JobState.Cancelled;
			}
		}
	}
	
	private void setState(final JobState newState) {
		synchronized (this.state) {
			this.state = newState;	
		}
	}
	
	private static String generateId(final String owner) {
		final String prefix = Job.class.getSimpleName();
		final String separator = "_";
		final String postfix = Long.toString(Calendar.getInstance().getTimeInMillis());
		
		// Make sure we don't go beyond the allowed length
		String candidateString = prefix + separator + owner + separator + postfix;
		if(candidateString.length() > GlobalConstants.TEXT_FIELD_CHAR_MAX_LENGTH) {
			log.warn("Job ID was too long when added in with owner string which had length " + owner.length());
			candidateString = prefix + separator + postfix;
		}
		
		
		assert candidateString.length() > GlobalConstants.TEXT_FIELD_CHAR_MAX_LENGTH : candidateString.length();
		
		return candidateString;
	}

	public Calendar getStartTime() {
		return startTime;
	}

	public Calendar getEndTime() {
		return endTime;
	}

	public String getResult() {
		return result;
	}

	public JobState getState() {
		return state;
	}

	public String getOwner() {
		return owner;
	}

	public Calendar getSubmissionTime() {
		return submissionTime;
	}

	public String getId() {
		return id;
	}
	
	public String getSsid() {
		return ssid;
	}
}
