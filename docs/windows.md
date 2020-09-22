---
description: Windows
---

# Windows 

Install NPcap driver: https://nmap.org/npcap/

## Notes

Kill all netcap processes:

    taskkill /IM "net.exe" /F

## Syntax coloring when viewing TCP / UDP streams 

Install vscode and the _vt-100_ extension.

Add file type association for .bin files to _vt100_ for automatic highlighting of ANSI colors.

If you display the documents in preview mode the escape sequences will be gone and the text colored.

## Directories

create the following directories:

1) \usr\local\etc

2) \usr\local\bin

Move the _net_ binary in here if you want to use Maltego.

3) \usr\local\etc\netcap

Move the folder with the exploits snippets from exploit db here, as well as your fingerbank API key.

3) \usr\local\etc\netcap\dbs

Move the contents of the Folder in here, these are the databases for the resolvers.
