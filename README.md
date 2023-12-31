# NLAM Agent
Service intended for Microsoft AD servers that allows secure ADSI abstraction accessible from remote hosts.

Bypasses some issues (namely password manipulation) that occur when using LDAP.

# Libraries

This project links multiple libraries:

[libconfig](https://github.com/hyperrealm/libconfig) available under GNU LGPLv2.1 License
[json-c](https://github.com/json-c/json-c) available under MIT License
[OpenSSL](https://www.openssl.org/) available under Apache License v2.0
Windows API libraries, packaged with Microsoft Windows under a proprietary license

# Build instructions

## Basic build

This project depends on [MSYS2](https://www.msys2.org/), utilizing Autotools as a build system.
All libraries listed above are build dependencies, and as such, must be installed to compile this project.

To then compile the project, run these commands, in order:

```
$ autoreconf -i
$ ./configure
$ make -j16
```

## NSIS installer

To create the project installer, [pedeps](https://github.com/brechtsanders/pedeps) must be accessible to MSYS2 (under PATH)
The easiest way to accomplish this is to simply copy the binary archive contents to MSYS2's /bin path.

Additionally, to compile the installer, [NSIS2](https://nsis.sourceforge.io/Download) must be installed


To create an installer, first compile the project using the instructions under Basic build.

Next, run the `prep-nsis.sh` script. This will package all dependencies and the binary into the staging directory

Lastly, compile `nsis/agent.nsi` (using `makensisw.exe` from NSIS). This will create an installer package in the project's root direcotry 

## PDB debug symbols

To create debug symbols in PDB format, [cv2pdb](https://github.com/rainers/cv2pdb) must be accessible to MSYS2 (under PATH)
The easiest way to accomplish this is to simply copy the binary archive contents to MSYS2's /bin path.

With cv2pdb installed and the project compiled, simply run the `mkpdb.sh` script in the project directory. This will output
`nlamagent-pdb.exe`, an NLAM Agent executable with debug symbols stripped, and `nlamagent.pdb`, the debug symbols in PDB format
