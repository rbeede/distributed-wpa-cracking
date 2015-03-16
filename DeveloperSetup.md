# Prerequistes #

  1. A Linux system
    * Use an Ubuntu Virtual Machine if you like
  1. gcc/g++ installed
  1. Perl 5.8 or later
  1. A rainbow table
    * Try this torrent http://code.google.com/p/distributed-wpa-cracking/downloads/detail?name=wpa_psk-h1kari_renderman.torrent&can=2&q=
  1. Public and private ssh keys with no password for automatic running
  1. ssh and sshd (usually included in your Linux distro)
  1. You may wish to use the Eclipse IDE with CDT http://www.eclipse.org/cdt/
    * Or whatever text editor you like
  1. SVN 1.6.15 http://subversion.apache.org/packages.html or later
    * For Windows I like Win32Svn in the plain svn-win32-1.6.15.zip form

# Environment Setup #

Ensure that the compiler, Perl, ssh, svn, etc. are in your system path for the easiest setup.

# Getting the source #

Just follow the directions at http://code.google.com/p/distributed-wpa-cracking/source/checkout

# Special Note About Checking In Code #

  1. You have to be a "Project committer" in the project
  1. You have to specify the --username parameter like this `svn ci -m "comment about check-in" --username MYUSERNAME@gmail.com`

# Building #

The perl code doesn't need any special build commands.

For the C/C++ code just do a normal **make** in the source directory.

For the scripts that assist in capturing wireless packets they should already be bundled into a virtual machine image.  In addition you could play with them in the source tree if you like.  No special build commands should be needed.  Note that they may be hard coded in configuration for the virtual image OS and tools.

# Configuration #

There should be a configuration file used by the Perl code for handling everything.