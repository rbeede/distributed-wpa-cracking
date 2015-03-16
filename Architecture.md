# Overview #

A large rainbow table of pre-generated wireless encryption handshakes will be divided up among a number of worker nodes.  The table consists of a large number of well known wireless SSIDs along with a dictionary of hundreds of thousands of common password variants.  The table used will have a complete size of 40GB.  The table is divided into separate files for each wireless network SID.  There are 1000 files each about 40MB in size.

One master node will have software that can start via ssh the code on the worker nodes.  The code binaries will be shared via NFS along with an output directory on the share.  For our implementation the rainbow table will be copied to each worker node manually to provide a local copy to decrease required startup time of local worker nodes.  This could also have been done via an NFS share to simplify deployment.

Each worker node will load a certain portion of the rainbow table completely into memory.  The portion will be given by command line arguments to the worker node binary.  The code on each worker will then run as a service accepting jobs from the master node by listening on a TCP socket.

A command on the master node will specify input capture data for a job.  A job will then be triggered by the master who will give each worker node a copy of the wireless capture data (via NFS share) and instruct them to start processing via a TCP socket start command.  The master node does NOT maintain this TCP connection for the duration of the job.

If a worker finds a solution it will output the result to a file on disk as specified by the job command from the master.  The master node will query worker nodes periodically to determine their current status.  The solution, if found, will be available in a SOLUTION file in the job's output directory.  If all nodes finish with no solution then no SOLUTION file will exist.

If a network error occurs the master will try to reestablish the connection since the worker may still be doing actual work.

All worker nodes will log to a file in the job output directory.

# Worker Node #

We'll need to modify coWPAtty to accept some command line arguments at startup, calculate its byte offsets of the rainbow table, and listen on a tcp socket. It should also save the found solution (if any) to disk and have a way to kill a running thread that is doing a search when it receives a signal via tcp.

Only 1 job should be allowed to run at a time.  No queue on the worker is necessary.

# Master Node #

Java web application that will handle job submission and queue.  It will also be responsible for starting the worker nodes via ssh per a pre-defined configuration.

It also enforces that the rainbow table SSID files are all the same byte size.  It handles calculating what ranges each worker node will do.

# Master to Worker Node Communication #

The master will send a tcp packet.  The master will be responsible for queuing jobs.  The TCP connection is closed after each message/response.

Contents will be:

START\0\31jobidF3234\0\31/var/length/path/to/wifi.pcap\0\31/var/length/path/to/job/output/dir/\0\31SSID Case Sensitive Name\0\31\4

Where \0 is the null character indicating the end of a string (8-bit chars)
\31 means US or the ASCII Unit Separator which indicates the end of a text field value.
\4 means ASCII End of Transmission which is a field to signal when the data is done.

Assume an individual string field length limit of 1024 bytes including the null termination char.
Assume a maximum packet size of 4096 bytes.

So the first text field indicates the tcp packet type.  START (case sensitive) means start a new job.  If a job is already running on a node return an error as defined below.  Otherwise it returns:  SUCCESS\_START\0\31jobidF32234\0\31\4

2nd field is the job id the master wants.  It could be any string of valid file path characters.  It will probably be more like jobid + epoch timestamp.

3rd field is the complete pathname to the wifi capture file.  The master will specify a path that is on the NFS share which will already be available to the worker nodes just like a local file would be.

### Worker Node Service Startup (not job start) ###

The worker node gets the following as startup command line parameters:

> --cluster-port 54321

> --cluster-rainbow-table /localdata/path/dir/with/sids/files/      (seeing this puts cowpatty into the special loading mode)

> --cluster-rainbow-table-start-offset 12345   (byte offset start of first record (inclusive) for every rainbow table SSID file, master node will enforce that all SSID files have the same byte size)

> --cluster-rainbow-table-end-offset 54321   (byte offset end record (exclusive) for every rainbow table SSID file, this is the next byte after the last record this node should attempt, for the last node it may actually be past the last byte of the file)

> --cluster-log /home/nfs\_share/hostname.log   (file where local node actions are logged that aren't specific to a job)

**These parameters are for debugging purposes**

> --cluster-rainbow-table-number-records 996123  (number of total records in each SSID file, same for all SSID)

> --cluster-rainbow-table-record-start 0  (where this node is starting in the total number of records, 0 indexed)

> --cluster-rainbow-table-record-end 123  (last record, inclusive, in total number of records that this node should try, 0 indexed)

> --cluster-node-rank 0-(n-1)	(this nodes rank, 0 indexed)

> --cluster-node-count 8	(number of worker nodes total)




Each worker node should log to a file in the /home/nfs\_share/jobresults/basedir/jobidF3234/ directory:
> hostname\_of\_worker\_node\_jobidF3234.log		(flush output right away to log too)

The worker node that finds the solution should also save a file in the output directory with the solution.  Call it SOLUTION
> The log file should also note that the worker found the solution.
> The master will know the path to find the SOLUTION file.

Each line in the log file should have a timestamp.  I like the format  yyyy-mm-dd hh:mm:ss.mili timezone (+00:00)



Querying job status

Packet looks like:  STATUS\0\31\4

Worker node returns one of:
> STATUS\0\31LOADED\0\31\4							(just started up and have already loaded rainbow table into memory, ready for query)

> STATUS\0\31RUNNING\0\31jobidF3234\0\31\4			(currently running job with given id)

> STATUS\0\31FINISHED\0\31jobidF3234\0\31\4			(last job finished was jobidF3224, ready for next query, only remembers last one finished)

> STATUS\0\31KILLED\0\31jobidF3234\0\31\4			Job was killed before it could finish.


Killing job on nodes

Suppose user wants to cancel a running job or one of the worker nodes found the solution.  The other worker nodes need to be told to stop trying.

KILLJOB\0\31jobidF32234\0\31\4

Response will either be error if that job wasn't in the running state or the following success message:

STATUS\0\31KILLED\0\31jobidF32234\0\31\4

Doing a kill on a job that is already in the FINISHED state does not change it to a KILLED state but instead gives an ERROR back.



ERRORS:


ERROR\0\31Error Message text goes here\0\31\4

Example text messages:
> Node is already busy with another job of id XYZ

> Could not kill non-running job with id XYZ