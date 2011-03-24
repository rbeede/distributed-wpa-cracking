package com.google.code.distributedwpacracking.master;

import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;

import com.google.code.distributedwpacracking.master.utils.WorkerNodeManager;

/**
 * @author Rodney Beede
 * 
 * Singleton using the enum method which also provides serialization and protects against reflection
 * See http://stackoverflow.com/questions/70689/efficient-way-to-implement-singleton-pattern-in-java
 * 
 * Access with GlobalData.INSTANCE or the traditional GlobalData.getInstance()
 *
 */
public enum GlobalData {
	INSTANCE;
	
	
	public static GlobalData getInstance() {
		return GlobalData.INSTANCE;
	}
	

	private final Collection<Job> jobs = new CopyOnWriteArrayList<Job>();
	private final LinkedBlockingQueue<Job> jobQueue = new LinkedBlockingQueue<Job>();
	
	public synchronized void enqueueJob(final Job job) {
		this.jobs.add(job);
		this.jobQueue.add(job);
	}
	
	/**
	 * The actual {@link Job} element could have its internal state change, but its membership in the list cannot.
	 * 
	 * This is a historical list of all previously ran jobs and those that may still need to be run.
	 * 
	 * A separate blocking queue is used for other jobs.
	 * 
	 * @return Unmodifiable collection of the jobs
	 */
	public Collection<Job> getJobs() {
		return Collections.unmodifiableCollection(this.jobs);
	}
	
	public LinkedBlockingQueue<Job> getJobQueue() {
		return this.jobQueue;
	}
	
	
	public WorkerNodeManager getWorkerNodeManager() {
		return new WorkerNodeManager(WebAppConfig.getInstance().getWorkerNodes());
	}
}
