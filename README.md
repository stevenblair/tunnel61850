# IEC 61850 GOOSE and Sampled Value Tunnelling using UDP #

## Installation using Eclipse ##

 - Install MinGW and add `C:\MinGW\bin;` to `PATH` in the Project Properties > C/C++ Build > Environment options. (Other compilers should work too.)
 - In Project Properties > C/C++ Build > Settings > GCC Compiler Includes, set `"${workspace_loc:/${ProjName}/Include}"` as an include path.
 - In Project Properties > C/C++ Build > Settings > MinGW C Linker, add `wpcap` and `ws2_32` (assuming you are using Windows) to "Libraries" and add `"${workspace_loc:/${ProjName}/Lib}"` and `"C:\MinGW\lib"` to "Library search path".
   - With Linux, use `pcap` instead of `wpcap`, and just add `"${workspace_loc:/${ProjName}/Lib}"` to the  "Library search path".
 - The WinPcap library files and header files (from http://www.winpcap.org/devel.htm) have been included in the repository for convenience. The PC must also have the WinPcap driver installed (either by installing Wireshark, or from http://www.winpcap.org/install/default.htm).
   - With Ubuntu, libpcap can be installed using `sudo apt-get install libpcap-dev`.
   - Remember that, on Linux, **libpcap needs to run as root**, so either start Eclipse or run the compiled binary from the Terminal with `sudo`. Alternatively, you can grant the binary the [capability to access the network interface](http://packetlife.net/blog/2010/mar/19/sniffing-wireshark-non-root-user/) using: `sudo setcap cap_net_raw,cap_net_admin=eip /path_to_project/tunnel61850/Release/tunnel61850`.


## Compile and run using Linux Terminal ##

```sh
sudo apt-get install libpcap-dev                           # install pcap

gcc -Wall -O3 interface.c main.c -lpcap -o tunnel61850     # compile
sudo ./tunnel61850                                         # run
```

