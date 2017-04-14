FS2ATD - FileSystem To Advanced Threat Defense
v1.0 (2017) Barry O'Brien (barry_obrien@mcafee.com)

Monitors directories recursively on a fileserver or FTP server for new exe. Checks the new file reputation in Threat 
Intelligence Exchange (TIE) for Enterprise Reputation, GTI Reputation, and ATD Reputation. If the file has a bad 
reputation it is quarantined. If the file has a good reputation it is passed. If the file has an unknown reputation it 
is sent to Advanced Threat Defense (ATD) for analysis. While ATD analyses the file it is encrypted on the server 
filesystem with a Read Me explaining that the file is being analysed. After ATD has completed the analysis the file 
reputation is updated in TIE. If the file is convicted it is quarantined.

Prerequisites:
*   dxlclient module for Python (https://pypi.python.org/pypi/dxltieclient/0.1.0)
*   watchdog module for Python (https://pypi.python.org/pypi/watchdog/0.8.3)
*   pycrypto module for Python (https://pypi.python.org/pypi/pycrypto)
*   atdlib module for Python (https://github.com/passimens/atdlib)

Before using:
*   Ensure that your OpenDXL is functioning correctly; correct brokerlist and certificates in .\dxlclient.config
*   Input your ATD IP address, username, and password, in ATD.__init__()
*   The ATD user must have REST access.
*   Ensure your certificates are authorised in Send Restrictions to "TIE Server Set Enterprise Reputation" in ePO

To operate, run main.py from a command line with the path you want to monitor as an argument. If you do not supply 
an argument then the same directory as the script will be used (i.e. ".\<dir>")
