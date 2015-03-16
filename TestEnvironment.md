This test environment was provided by Cisco.  They loaned a machine and hosted it in their Boulder office data center.  It will be available from Feb 2011 until May 2011.

Rodney Beede is an intern for Cisco until May 2011.



# Hardware #

Cisco UCS C210 M1 General-Purpose Rack-Mount Server with 64GB of ram and two quad core Intel Xeon processors (8 logical cores).

16 137GB SAS drives for a total of 2,192GB of disk space configured in a single RAID5.

6 Gigabit Ethernet cards.  Only two are connected.

1 ILO Ethernet card, connected.

# Host Operating System #

VMware vSphere HypervisorTM (ESXi) 4.1

# Virtual Machines #

There are 9 total VMs.  All are on a private network.  Only 1 is on the public Internet.  You SSH into this machine which serves as an access point and job task manager.  You don't run actual jobs on this node since it is smaller than the others.  It is used to ssh onto other machines.

Ubuntu Server 64-bit 10.10 is used for each VM.

univ-colo-vm-198-41-9-71.cisco.com:22 is the SSH access for this machine.  It has a private network address of 192.168.0.1.

Node workers are in the private network range specified in the [#Networking](#Networking.md) section.

Your home directory is shared among all virtual machines.  Your login username is the same across all, but your password is not synchronized.  It is recommended to setup ssh key pairs in your home directory for access to other machines.

See the /etc/hosts file on any VM for dns entires to use.

Contact Rodney Beede if you need your SSH key and login.

# Networking #

ILO network address (accessible only by Cisco employees with VPN access) is 10.94.170.229.

Public Internet addresses:
  * 198.41.9.70
    * /24 subnet
    * 198.41.9.2 gateway
    * No specific DNS (use Google's 8.8.8.8 public DNS)
    * bldr-vh29-dmz.cisco.com is the DNS name
    * This is the VMware Hypervisor ESXi 4.1 host system

  * 198.41.9.71
    * Same as 198.41.9.0/24
    * univ-colo-vm-198-41-9-71.cisco.com
    * This is the Virtual Machine cluster master node accessible via the public Internet over ssh

  * 198.41.9.72
    * Used by Rodney only for doing file copies to master

Private Network addresses:
  * 192.168.0.0 – 192.168.0.15
    * /28 subnet
    * Netmask is 255.255.255.240
    * No gateway
    * No DNS
      * /etc/hosts on all VMs have dns names set
    * You access these nodes from the master VM node univ-colo-vm-198-41-9-71.cisco.com all via ssh.

## Access ##

ILO KVM console access is done via Cisco's VPN.  Only Rodney Beede has access to do this.  Used to reboot machine.

### VMware access to host operating system ###

Only Rodney Beede has access to do this.

### SSH to VMs ###

See [#Virtual\_Machines](#Virtual_Machines.md) section

# Common Account #

DIST-WPA is the username and group for a common user for running the actual project code and services.

ssh -i /home/DIST-WPA/group-shared/id\_rsa DIST-WPA@192.168.0.X for an interactive session for debugging (login to the master as your own username first so we can tell who is using the common account).

Place code files in /home/DIST-WPA/group-shared
This directory has the group sticky bit set and the default umask is 007.  Please make sure you leave files/folders group readable and writable.

An automated script run from the master will automatically ssh onto all nodes for starting the system.

The command is `TODO`

# Rainbow Table #

Each local node (not the master) has a directory **/localdata/** which holds the 40GB rainbow table.

# Master node web access #

Requires username and password too.  Self-signed SSL certificate.

https://univ-colo-vm-198-41-9-71.cisco.com:8443/distributed-wpa-cracking-master/welcome.jspx

# References #

https://help.ubuntu.com/community/SettingUpNFSHowTo