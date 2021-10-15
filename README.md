# EXE4J Configuration Extractor

This script helps reverse engineering Portable Executable files created with EXE4J by extracting their configuration data.
Especially if EXE4J was used to not wrap a JAR file but only to launch it, the configuration is all you can get from such a file.

Note: Since install4j also uses EXE4j, it works on those executables too. Use 7zip to unpack embedded .JAR files.
