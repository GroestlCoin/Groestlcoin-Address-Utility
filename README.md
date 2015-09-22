                                 GroestlCoin-Address-Utility
===============================================================================
Works on Windows, Linux and OS X (with Mono)

Unpack ZIP archive with 3 files:
	GrsAddress.exe
	BouncyCastle.Crypto.dll
	ThoughtWorks.QRCode.dll

Windows
-----------
Just run GrsAddress.exe

Linux
---------------------
1. Install Mono
	On Ubuntu:
		apt-get install mono-complete

2. Set Execution mode for file GrsAddress.exe:
	chmod +x GrsAddress.exe

3. Run:
	./GrsAddress.exe


OS X
---------------------
1. Download and install Mono for OS X:
	http://www.mono-project.com/download/

2. Set Execution mode for file GrsAddress.exe:
	chmod +x GrsAddress.exe

3. Run:
	mono GrsAddress.exe


BUILD
-------------
This project has two dependencies:

1. the BouncyCastle Crypto library.
2. ThoughtWorks QRCode DLL

Get BouncyCastle from http://www.bouncycastle.org/csharp/  (just the compiled assembly is fine).


