# Introduction #

Simply append your progress as you go with brief details of what you've done and plan on doing next.

Use headings with the format YYYY-MM-DD HH:MM - yourname - brief subject

Newest at top
# 2011-04-21 20:28 - Arpit Sud - New test data #

New test data for SSID linksys uploaded.

# 2011-04-20 15:08 - Rodney Beede, Ryan Kroiss - Code work #

Working all day on getting the code to work with all 1,000 SSID.

# 2011-04-16 18:34 - Rodney Beede, Arpit Sud, Ryan Kroiss - CODING MAYHEM! #

Master now passes SSID with job start.  Added struct for rainbow table entries.


# 2011-04-14 13:53 - Arpit Sud - Added packet capture data to testdata #

Added packet capture data for testing purpose to testdata.


# 2011-04-13 21:20 - Ryan Kroiss - Fixed some issues with job execution #

Worker actually starts job, but there is some error occurring so job goes nowhere.


# 2011-04-13 17:14 - Rodney Beede - Fixed master web app #

Bug in code was closing TCP socket too soon.  Fixed so master app works correctly when interacting with worker nodes.


# 2011-04-12 23:20 - Ryan Kroiss - Initial tests #

I started doing some testing using the web app.  Right now, there are still some kinks to work out.  The workers appear to get the STATUS messages, but it doesn't seem like the master is hearing from them.  We'll have to figure out which side is having the problem.  It might be an issue with the worker not trying to reestablish the connection if master is closing the connection after each message.


# 2011-04-10 17:00 - Ryan Kroiss - Loading rainbow table #

Started loading rainbow table into memory.


# 2011-04-10 13:00 - Ryan Kroiss - Log messages #

Wrote function to log message to a file.  It handles varying arguments.


# 2011-04-09 12:00 - Rodney Beede - Code updates to master #

I've updated the code so the master inspects the rainbow table files and determines the byte offsets for each worker node.  I had some trouble since a bug in Java caused files with characters in an unknown character set to be inaccessible.  I had to rename the file in question to fix this.


# 2011-04-08 08:30 - Rodney Beede - Updates to master #

Arpit wants the master code to pre-calculate the offsets needed for every worker node.  He figures this will be less work and file I/O for each worker node to have to do.  I will make the necessary code changes this weekend.

# 2011-03-26 13:37 - Ryan Kroiss - Worker node code #

I'm working on the worker code.  For the moment, I'm just testing locally.  I hope to get the communication side of things up soon.

# 2011-03-24 12:12 - Rodney Beede - Setup of master node #

Spent 2 hours with a weird Tomcat slow startup issue.  I had to reboot the server and it just went away.

Got https://univ-colo-vm-198-41-9-71.cisco.com:8443/distributed-wpa-cracking-master/welcome.jspx setup as a secure URL with usernames.

# 2011-03-24 01:13 - Rodney Beede - Coding on master node #

The code is ready for use.  Some minor tweaks could be made later on to improve performance if really needed.

Next step is to get installed on cluster for testing and use.

# 2011-03-23 15:56 - Rodney Beede - Coding on master node #

Working on the code for the master node today.  Hope to have it usable by this evening and running.

# 2011-03-10 15:56 - Ryan Kroiss - Added server code to repo #

Added the server code to the source code repository.  It's just a skeleton of what
we need, but it should be a start.

# 2011-03-10 13:15 - Ryan Kroiss - Listener for master node #

Created simple socket program to listen for messages over a certain port.  This
will run on the master.  When it receives a valid message, it will start up the
client nodes to process the request.

# 2011-03-09 22:18 - Arpit Sud - Data Capture script   #

Uploaded script for data capture to SVN.

# 2011-03-09 15:26 - Arpit Sud - How to Capture Data   #

Created the Wiki page HowtoCaptureData.

# 2011-03-07 16:36 - Ryan Kroiss - Up and running #

Successfully accessed cluster and checked out code

# 2011-03-05 23:15 - Rodney Beede - Data on cluster #

Spent several hours getting the 36GB rainbow table copied onto each node's local disk.

Setup ssh\_known\_hosts on all nodes so all nodes would already be auto-trusted for all users.

E-mailed team about performance of coWPAtty unmodified and standalone from disk.  Does it make sense when it can run a lookup over ~996,000 passwords from disk in about 36 seconds?  What advantage is there in pre-caching the rainbow table in memory?  Multiple queries as a service perhaps?

# 2011-03-04 10:27 - Rodney Beede - Cluster Online #

The hardware and VMs are all setup and usable for login.  I will copy the ssh\_known\_hosts and rainbow table to all machines today.

# 2011-03-03 11:11 - Rodney Beede - RAM replaced #

The ram has been replaced.  I'm going to try to get all nodes online today.

# 2011-02-28 20:28 - Rodney Beede - Cluster almost ready #

I've finished the OS configuration of the VMs for 1 master and 1 node.  All I need to do is adjust the server times and clone the worker node.

In addition I need to get in contact with Cisco about increasing the ram to 64GB.

# 2011-02-28 20:09 - Rodney Beede - Cluster hardware #

I have the master node mostly configured.  I accidentally locked myself out of ssh and will reset it.

# 2011-02-28 7:54 - Rodney Beede - Cluster hardware #

We received another public IP address allocation from Cisco.  I've updated the test environment page accordingly.

# 2011-02-26 11:22 - Rodney Beede - Cluster hardware and architecture #

Cisco has removed the faulty memory from the hardware.  I'm running memtest on it now.

I wrote some documentation on architecture ideas.

# 2011-02-24 18:44 - Rodney Beede - Cisco hardware for the cluster #

The machine has been give an IP and the information placed in TestEnvironment.  However a hardware issue has arisen which won't be addressed until tomorrow.

# 2011-02-23 20:46 - Rodney Beede - Cisco hardware for the cluster #

This is taking longer than I would have liked.  The machine is setup with the OS, but Cisco is taking a long time to get a public Internet IP address for the machine.  I hope to have it by this Friday.

# 2011-02-23 20:41 - Rodney Beede - Got the project wiki and hosting up #

I managed to get a Google Code project hosting space setup with the wiki for tracking our progress on this class project.  We'll use the svn repository for storing our code.  It has a 4GB size limit which should be big enough to even hold the virtual machine running http://www.backtrack-linux.org/