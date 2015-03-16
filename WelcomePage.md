# Introduction #

This is a project undertaken by three graduate students at the University of Colorado in the Spring of 2011.  Our goal was to create a distributed system for doing WPA1/2 password lookups on a large rainbow table.

The rainbow table was obtained from http://www.churchofwifi.org/Project_display.asp?pid=90 and the wpa\_psk-h1kari\_renderman.torrent torrent.

# Project Links #

[Developer journals of work](DevelopmentJournal.md)

[Getting the environment setup and building](DeveloperSetup.md)

[Testing environment](TestEnvironment.md)

[Architecture](Architecture.md)

[Installing a build for use in a cluster](HowtoInstall.md)

[Instructions for capturing wireless packets](HowtoCaptureData.md)

[Instructions for using the distributed system to analyze capture data](HowtoUse.md)

# Project Proposal given for class #

## Abstract ##

There are tools for brute-force cracking WPA1/2 such as coWPAtty and aircrack-ng.  coWPAtty was one of the first to support rainbow lookup tables of precomputed SSID and a large dictionary of commonly used passwords.  Our project will look to improve on the lookup technique of coWPAtty in searching the rainbow table either by modification to the existing code to work on a distributed cluster of machines or with our own implementation.  If time permits we will also look into generating new rainbow tables across the cluster which feature coWPAtty currently lacks.

## Group Members: ##
  * Rodney Beede
  * Ryan Kroiss
  * Arpit Sud

# Project Timeline and Roles #

| **Due Date** | **What** | **Who** | **Date Completed** |
|:-------------|:---------|:--------|:-------------------|
| February 18 | Study coWPAtty code (reuse?) | Ryan | 2011-02-18 |
| February 18 | Hardware Setup | Rodney | Expected 2011-02-25 |
| March 4 | Coding:  Load and distribute parts of rainbow table | Rodney |  |
| March 4 | Coding:  Scripts to automate and verify wireless data capture | Arpit |  |
| March 21 | Code in usable state near final version | All |  |
| March 21 | Coding:  Search algorithm and record found answer to disk | Arpit |  |
| March 21 | Coding:  Comm protocol signal other nodes answer found so stop working | ??? |  |
| March 21 | Coding:  Benchmark stats (not the actual graphs) from program | ??? |  |
| March 21 | Testing:  Capture WPA2 wireless data for testing (knows & unknowns) | All |  |
| March 21 -25 | Spring Break | All | 2011-03 |
| April 15 | Testing:  Test capture data by running attempt against SSIDs and passwords in the rainbow table.  Record performance.  Known and unknowns. | Ryan |  |
| April 22 | Testing:  Optional – run cluster on Amazon EC2 and record performance | Any |  |
| April 30 - May 5 | Sat – Thu; Finals Week | All |  |
| May 2 | Report:  Graphs of report data and conclusions.  PowerPoint. | All |  |
| May 2 | Monday, 7:30PM-10:00PM; Final Exam presentation | All |  |

# References #

http://www.willhackforsushi.com/?page_id=50

http://wirelessdefence.org/Contents/coWPAttyMain.htm

http://openciphers.sourceforge.net/oc/wpa.php