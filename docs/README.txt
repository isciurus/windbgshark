		Windbgshark: the unified traffic instrumentation tool
		
  What is it?
  -----------

  This project includes an extension for the windbg debugger as well as a 
  driver code, which allow you to manipulate the virtual machine network
  traffic and to integrate the wireshark protocol analyzer with the windbg
  commands.

  The motivation of this work came from the intention to find a handy
  general-purpose way to debug network traffic flows under the Windows OS for
  the purposes of dynamic software testing for vulnerabilities, for reverse
  engineering of software and just for fun.

  Theory of operation
  -------------------
  
  The main idea is to rely on the Windows Filtering Platform capability to
  inspect traffic at the application level of OSI (however, the method works
  well on any level introduced by the WFP API). This gives us a way to
  intercept and modify any data, which goes through the Windows TCP/IP stack
  (even the localhost traffic), regardless of the application type and
  transport/network protocol. Modification and reinjection also work excellent:
  the operating systems does all the dirty work, reconstructing the transport
  and network layer headers, for example, as if we were sending the data from
  the usermode winsock application.

  This tool needs a virtualized enviroment (it works fine with VMWare 
  Workstation now) with windbg connected to the virtual machine as a kernel
  debugger. Installation is done in two steps: driver installation and
  extension loading in windbg. Driver intercepts network traffic, allows the
  windbg to modify it, and then reinjects packets back into the network stack.
  The extension on its turn implements simple interface for packet edit and
  also uses Wireshark to display data flows. The extension is executed on the
  host machine, while the driver is located on the virtual machine. To interact
  with its driver, windbg extension sets the corresponding breakpoints with its
  own callbacks right inside the driver code. Every time a packet comes in or
  out, a breakpoint is hit and the windbgshark extracts the app-level payload
  of the current packet, constructs a new pcap record and sends it to
  Wireshark. Before the packet is reinjected back, user may modify it, and the
  Wireshark will re-parse and show the modified record.

  The Latest Version
  ------------------
  
  Details of the latest version can be found on the Windbgshark google code
  page under http://code.google.com/p/windbgshark/.
  
  Installation (Quick Start)
  ------------
  
  You should prepare a virtual machine with Windows 7/Vista x64/x86 in VMWare
  workstation and the Windbg debugger (which is included in Windows Driver Kit,
  http://msdn.microsoft.com/en-us/windows/hardware/gg463009). When virtual
  machine is ready, you need to prepare it to interact with the windbg as a
  kernel debugger. This task is covered in
  http://www.ndis.com/ndis-debugging/virtual/vmwaresetup.htm.  The nicest way
  to configure interaction between Host and Guest OS is to leverage VirtualKD
  tool. This tool and documentation for it is located at 
  http://virtualkd.sysprogs.org/.
  
  To install Windbgshark Guest module, please, unpack the binary achrive
  somewhere on the Guest system (for example, C:\windbgshark) and run 
  ./guest/install_guest.bat scrips as Administrator. Please, do not delete or
  relocate this folder unless you would like to uninstall the Guest module
  (which is done by running ./guest/uninstall_guest.bat).
  
  Windbgshark Host module is essentially a single library, which is a windbg
  extension. To run the Host Windbgshark part you should first unpacke the
  binary somewhere on the Host system, then break into the debugger, then type
  in windbg console
	!load <windbgshark.dll_path>
  where <windbgshark.dll_path> is a full path to the windbgshark.dll either at
  ./host/x64/windbgshark.dll or at ./host/x86/windbgshark.dll, depending on
  the Host OS architecture. Please, do not delete or relocate the unpacked
  folder unless you would like to stop the Host module (which is done by typing
  !unload in the windbg console). The extension will try to find the Wireshark
  executable upon startup, so please ensure that Wireshark is installed and at
  %ProgramFiles%\Wireshark %ProgramW6432%\Wireshark or anywhere in %PATH%.
  
  Then type !windbgshark.help to get the list of commands and start playing
  with the tool. All the TCP/IPv4 packets should be captured by the tool and 
  visible in Wireshark window.
  
  Development and Bug Reporting
  -----------------------------
  
  If you would like to contribute ot suggest any helpful feature, please write
  the author at isciurus@gmail.com. To inform about the bug you can use
  google code issue tracker on the project page: 
  http://code.google.com/p/windbgshark/issues/list

  Restrictions
  ------------
  
  The tool is expected to be a proof-of-concept code rather than a reliable
  software product. There are lots of bugs here, also the main problems are:

  - Wireshark does not reload the pcap file automatically, you still need to
    press Ctrl + R every time you want to look at the changes. This sucks,
	yeah.
  - Only IPv4/TCP is supported now. It is quite easy to add IPv6 and non-TCP
    transport, nevertheless, it is not done yet.
  - The extension lowers virtual machine bandwidth dramatically (to the value
    of about 0.6Mb/s on my machine).
  - Whatever you find