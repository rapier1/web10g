Web10G Preliminary Documentation

What is Web10G? 
Web10g is a set of TCP stack kernel instruments as described by IETF 
RFC 4898 (https://www.ietf.org/rfc/rfc4898.txt). These instruments 
provide fine grained measurements of the internal actions of the TCP 
stack. This information can be used for diagnostics, TCP flow 
evolution research, statistics, logging, and so forth.  Note: As of version 
0.13 (Linux kernel 4.18) two new non-rfc4898 instruments have been added. 
These instruments track lost restransmits (LostRetransmitSegs in the perf
table) and RACK timeouts (RackTimeout in the stack table). Adding new
intruments to the kernel (as the stack changes) is one of the advanatges
of using Web10g. 

Where do I get Web10G? 
Kernel: https://github.com/rapier1/web10g
Module: https://github.com/rapier1/web10g-dlkm
Userland: https://github.com/rapier1/web10g-userland
 
The Web10G kernel provides the instruments and necessary data 
structures in order to capture detailed TCP stack data. The git repo is 
built against the Linuc kernel as provided by the official Linux 
repository at kernel.org.  
 
The Web10G kernel module a netlink based application binary 
interface that allows userland access to internal kernel metrics. The 
kernel module is provided as a separate code base in order to clearly 
delineate the ABI form the core instrument set. The kernel module is 
not a integral component of Web10g but provides the easiest access to 
the kernel instrument. Alternative methods of accessing the TCP stack 
data have been developed by other parties but are not provided as part 
of our offerings. 

The Web10G Userland consists of a library and example applications. 
The library is a relatively straightforward API that interacts with the 
ABI in order to give developers a consistent interface to the data. The 
example applications allow users to interact with the resulting data. 
These example applications are, for many users, are all that is 
necessary to start making use of Web10g data. They also provide a 
useful foundation for developers interested in building their own 
applications. 
 
How do I build Web10G? 
1) Fetch the Web10G kernel from GitHub at 
https://github.com/rapier1/web10g
2) Determine which kernel revision you like to build. Examples 
would include 3.10, 4.8, 4.14 and so forth. Keep in mind that 
the Web10g patches are built against the major revision of the 
kernel as determined by the git tag provided by kernel.org. 
Different operating systems may have specific patches that they 
apply against these kernels for their official releases. As such, 
when you build a Web10G kernel from the git repo you will be 
building against a generic kernel and not necessarily the kernel 
officially support by your specific Linux distribution. 
3) Check out the appropriate version of the Web10g enabled 
kernel. If you have decided to build kernel revision 4.14 you 
would checkout 'kis-0.12-4.14'. You can list all of the tags by 
issuing a 'git tag' command from within the source directory. 
**NOTE** Do not checkout any of the tags that are prefaced 
with 'web10g' - ONLY checkout tags prefaced with 'kis' 
(kernel instrument set). While this may seem odd the web10g 
tags were for a version of the software that included the kernel 
module within this repo. This is no longer supported and an 
external dynamically loaded kernel module now provides these 
functions. The web10g tags are only maintained for historical 
purposes. 
4) Configure the kernel using whatever method you are most 
comfortable with. However, you need to explicitly enable 
Web10g support. Under menuconfig this would be under  
Networking Support --> 
      Networking Options --> 
            TCP: Extended TCP statistics (RFC4898) MIB 
 
The option 'TCP: ESTATS strict ElapsedSecs/Msecs counters' 
will enable much higher resolution timestamps but at a notable 
performance penalty. In most cases this option isn't necessary 
for data collection. The .config file should now contain the lines 
CONFIG_TCP_ESTATS=y 
# CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME is not set 

5) Build and install the kernel with your preferred method. 
However, we do suggest that kernels be compiled with the 
appropriate package manager in mind. As such - on RedHat 
derived systems 'make rpm-pkg' will create an rpm of the 
kernel. On  Debian derived systems you would use 'make deb-
pkg'. Also, if you are on a multicore system you can dramatic 
speed up compilation using make -j[NumCores] where 
NumCores corresponds to the number of CPU cores/threads 
available. 
	   a. Be sure to install the kernel sources as well. If you have 
	   built a package these will be in the kernel-devel package. 
	   You will need these in order to build the Web10g kernel 
	   module. 
6) Reboot into the new kernel. 
7) Get the kernel module source from 
https://github.com/rapier1/web10-dlkm
8) List the tags in the repo with 'git tag' and checkout the tag that 
most closely corresponds to the kernel revision that you built. 
For example, if you have build kernel 4.16 you'd check out the 
tag 'kernel-4.13'. If you have build a 3.10 kernel you'd 
checkout out the tag 'pre-4.9-kernel'
9) Issue a 'make' command.
10) Copy the 'tcp_estats_nl.ko' file to the appropriate kernel 
modules directory with 'sudo cp tcp_estats_nl.ko 
/usr/lib/modules/`uname -r`/kernel/net/ipv4' and run 'depmod' 
to rebuild the modules list. 
11) Finally, install the userland libraries and applications. Get the 
source for these form https://github.com/rapier1/web10g-userland
12) Ensure that libmnl installed on your system. It's easiest to do 
this from the package system but a version of the libmnl source 
is available in the repo. 
13) Configure, build and install the web10g-userland. By default 
the web10g applications will be installed in to /usr/local/bin. 
14) Celebrate a job well done. 
 
How do I use Web10G? 
After installing all of the components of Web10g you will need to 
load the module and instantiate the collection process with the 
following commands
'sudo modprobe tcp_estats_nl'
'sudo sysctl -w net.ipv4.tcp_estats=127' 
 
You may also set a 'delay' period. This delay maintains the data 
associated with a specific TCP flow for a set period of time after the 
flow closes. This is useful when using an external application to 
monitor TCP flows (as opposed to building the Web10g triggers into 
the application itself). With this delay the external application can 
gather the last round of metrics associated with the closed flow. You 
can set the delay period with 
'sudo sysctl -w net.ipv4.estats_delay=[delay in ms]'

For example, the included application web10g-logger gathers metrics 
from all TCP connections every second. By setting the estats_delay 
parameter to 1500ms web10g-logger will be assured of gathering the 
end state of the each flow even if it has closed prior to data collection. 
However, keep in mind that the estats_delay parameter will cause 
increased memory pressure so be sure to set the value to the minimum 
value that will suit your data collection needs.  
 
Also, it is important to note that Web10g will only start collecting 
data after the collection process is instantiated. Any flows existing 
prior to setting net.ipv4.tcp_estats will not be reported.  
 
Several applications are includes in the web10g-userland these 
include:

web10g-logger: Print all metrics for all TCP flows periodically 

web10g-deltavars: Print the periodic difference between metrics for a 
given tcp flow 

web10g-getmib: List the available instruments supported by the kernel 

web10g-listconninfo: List all open TCP connections include the 
owner and process associated with the flow.

web10g-listconns: List all open TCP connection.

web10g-readvars: Read all or a subset of metrics for a given flow one 
time.

web10g-watchvars: Periodically print the current values for all metrics 
for a given TCP flow

web10g-recordread: Read a Web10g record of a given set of metrics 
for a flow. 

web10g-recordwrite: Write a record of Web10g metrics for a given 
TCP flow.

web10g-writevar: Write values to writable Web10g instruments. 
Generally this would be the TCP receive and send buffer parameters. 

