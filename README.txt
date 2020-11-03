
###### INTRODUCTION ######

gtester.py: client for GTP tunnel creation straight from your computer 

saegw.py: SAE gateway



###### INSTALLATION #######

1st
Check if you have the right kernel headers installed:

Example for RHEL, Fedora, CentOS:

rpm -q kernel-devel-`uname -r`


If not installed, try:

Example:

yum install kernel-devel-`uname -r`



2nd
Execute in the directory in which you unpacked the soft:

make




###### USAGE ######

Modify configs sections in the scripts,
make the scripts executable with chmod (if needed)

and run:

./gtester.py

or

./saegw.py
