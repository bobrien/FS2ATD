"""
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

To operate, run the script from a command line with the path you want to monitor as an argument. If you do not supply 
an argument then the same directory as the script will be used (i.e. ".\<dir>")
"""

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from Crypto.Cipher import XOR
from Crypto.Hash import MD5, SHA, SHA256

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel

from json import dumps
from time import sleep
from base64 import b64encode, b64decode
import atdlib
import sys
import os



class TIE:
    def __init__(self):
        """Setup DXL configuration"""
        dxl_config = DxlClientConfig.create_dxl_config_from_file(".\dxlclient.config")
        dxl_client = DxlClient(dxl_config)
        dxl_client.connect()
        self.tie_client = TieClient(dxl_client)

    def get_file_rep(self, hashes):
        """Get the file reputation of the passed hashes (MD5, SHA1, SHA256)"""
        return self.tie_client.get_file_reputation(hashes)

    def set_file_rep(self, hashes, filename, rep):
        """Set the Enterprise Reputation of the hashes (MD5, SHA1, SHA256)"""
        try:
            self.tie_client.set_file_reputation(rep, {
                HashType.MD5: hashes["md5"],
                HashType.SHA1: hashes["sha1"],
                HashType.SHA256: hashes["sha256"]
            }, filename=filename, comment="Reputation set via FS2ATD")
            return True
        # Return True for success but if the operation fails then return False so we can exit the script later.
        # Failure to update the TIE rep means ATD will get stuck looping the same file so we must exit on failure.
        except():
            return False


class ATD:
    def __init__(self):
        """Setup ATD"""
        self.atd_ip = ''
        self.atd_username = ''
        self.atd_password = ''

    def uploadtoatd(self, filename):
        """Upload the file to ATD"""
        atd = atdlib.atdsession()
        atd.open(self.atd_ip, self.atd_username, self.atd_password)
        jobid = atd.fileup(filename)
        jobtasks = (atd.jobtasks(jobid))
        atd.close()

        # We only need to return the taskid
        return {"taskid": jobtasks[0]}

    def taskstatus(self, taskid):
        """Check the status of the current ATD analysis"""
        atd = atdlib.atdsession()
        atd.open(self.atd_ip, self.atd_username, self.atd_password)
        status = atd.taskstatus(taskid)
        atd.close()
        return status

    def atd_md5(self, md5):
        """Check the result of the analysis using MD5. MD5 gives better accuracy than using taskId"""
        atd = atdlib.atdsession()
        atd.open(self.atd_ip, self.atd_username, self.atd_password)
        result = atd.md5status(md5)
        atd.close()
        return result


class Encrypt:
    def __init__(self):
        """Initialise the key. Must be 32 bytes."""
        self.key = str(0xD0AD5F62)

    def hashes(self, file_loc):
        """Calculate the hashes of the file.
        
        With the open file, read the content as a binary stream and then hash. 
        Return the hashes (MD5, SHA1, SHA256 as dict object.
        """
        open_file = open(file_loc, "rb")
        content = open_file.read()
        open_file.close()
        md5 = MD5.new()
        md5.update(content)
        sha1 = SHA.new()
        sha1.update(content)
        sha256 = SHA256.new()
        sha256.update(content)
        hash_dict = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
        return hash_dict

    def encrypt(self, content):
        """XOR the raw content with the key to encrypt the file"""
        cipher = XOR.new(self.key)
        return b64encode(cipher.encrypt(content))

    def decrypt(self, encrypted):
        """XOR the encrypted content with the key to decrypt the file"""
        cipher = XOR.new(self.key)
        return cipher.decrypt(b64decode(encrypted))

    def write_file(self, filename, content):
        """Overwrite the file with the encrypted or decrypted data"""
        w_file = open(filename, "wb")
        w_file.write(content)
        w_file.close()
        return True

    def lock_file(self, filename):
        """Lock the file that has been sent to ATD
        
        The lock is achieved by encrypting the content of the raw file then overwriting the raw file with the
        encrypted data. The file extension of ".lock" is added to the encrypted file.
        
        A text file is created with the same filename as the locked file but with "READ ME" appended. The text file
        informs the user of the ATD analysis of their file.
        """
        lock_filename = filename + '.lock'
        raw_file = open(filename, "rb")
        raw_content = raw_file.read()
        encrypted_data = self.encrypt(raw_content)
        raw_file.close()
        self.write_file(filename, encrypted_data)

        # If the renaming of the file fails due to a previous version of the file existing then remove the previous.
        try:
            os.rename(filename, lock_filename)
        except WindowsError:
            os.remove(lock_filename)
            os.rename(filename, lock_filename)

        readme = open(filename + "_READ_ME.txt", "w")
        readme.write("Your file has been locked while it is analysed for advanced malware.\n\n"
                     "Please check back in 5-10 minutes to see if the file has passed.\n\n"
                     "If the file is not unlocked after 15 minutes please contact your administrator")
        readme.close()
        return True

    def unlock_file(self, filename):
        """Unlock the file that has been sent to ATD if the result is clean

        XOR the encrypted file with the password to decrypt the file. Remove the ".lock" file extension. 

        Delete the "Read Me" text file.
        """
        lock_filename = filename + '.lock'
        lock_file = open(lock_filename, "rb")
        lock_content = lock_file.read()
        raw_content = self.decrypt(lock_content)
        lock_file.close()
        self.write_file(filename, raw_content)
        os.remove(lock_filename)
        os.remove(filename + "_READ_ME.txt")
        return True


class Quarantine:
    @staticmethod
    def move_file(filelocation):
        """Move the file to the quarantine
        
        Create the quarantine directory if it doesn't exist
        then attempt to move the file. 
        If the file move fails then append "_copy" to the file and attempt to move again.
        """
        quarantine = 'C:\FS2ATD_QUARANTINE\\'
        filename = os.path.basename(filelocation)
        if not os.path.exists(quarantine):
            try:
                os.mkdir(quarantine)
            except():
                print "\n> Unable to create C:\QUARANTINE directory.\nExiting program.\n"
                exit()
        else:
            try:
                os.rename(filelocation, quarantine + filename)
                print "\n> File QUARANTINED to " + quarantine + filename
            except WindowsError, e:
                print e


class Event(FileSystemEventHandler):
    def __init__(self):
        """Set up our dicts"""
        self.statuses = {-1: "failed", 0: "error", 1: "complete", 2: "complete", 3: "analyzing", 4: "queued"}
        ''' ATD analyses statuses from ATD API Guide -
            When analysis is complete, the istate=1 or 2.
            When sample is waiting in the queue, the istate=4.
            When sample is being analyzed, the istate=3.
            When analysis is failed, istate=-1.
            Only when the istate=1 or 2, continue to get the results.
        '''

        # Descriptions of the TIE & GTI reputations according to severity class
        self.rep_descriptions = {
            100: "KNOWN_TRUSTED_INSTALLER",     # PASS
            99: "KNOWN_TRUSTED",                # PASS
            85: "MOST_LIKELY_TRUSTED",          # PASS
            70: "MIGHT_BE_TRUSTED",             # PASS
            50: "UNKNOWN",                      # ATD
            30: "MIGHT_BE_MALICIOUS",           # QUARANTINE
            15: "MOST_LIKELY_MALICIOUS",        # QUARANTINE
            1: "KNOWN_MALICIOUS",               # QUARANTINE
            0: "NOT_SET"                        # ATD
        }

        # Descriptions of the ATD severities according to severity class
        self.atd_descriptions = {
            -1: "KNOWN_TRUSTED",                # PASS
            0: "MOST_LIKELY_TRUSTED",           # PASS
            1: "MOST_LIKELY_TRUSTED",           # PASS
            2: "MIGHT_BE_TRUSTED",              # PASS
            3: "MIGHT_BE_MALICIOUS",            # QUARANTINE
            4: "MOST_LIKELY_MALICIOUS",         # QUARANTINE
            5: "KNOWN_MALICIOUS",               # QUARANTINE
            -2: "NOT_SET"
        }

        # We need to map the TIE/GTI and ATD reputations/severities for inserting ATD reps to TIE
        self.reps_map = {-1: 99, 0: 85, 1: 85, 2: 70, 3: 30, 4: 15, 5: 1, -2: 0}

        # Dicts of severities according to action (i.e. pass/quarantine)
        self.rep2pass = {100, 99, 85, 70}
        self.rep2quar = {30, 15, 1}
        self.atdsafe = {-1, 0, 1, 2}
        self.atdquar = {3, 4, 5}


    def dispatch(self, event):
        """The event listener which detects the changes to the filesystem"""

        # We only want "File Created" events
        if type(event).__name__ == "FileCreatedEvent":

            # The location of the "File Created" according to our event listener
            file_location = event.src_path
            file_ext = os.path.splitext(file_location)[1]

            '''For now, only analyse executables with .exe extension.
            In future, "Magic Byte" detection will be put in place.
            Also forthcoming, other file types besides Windows Executables.
            '''
            if file_ext == ".exe":

                # Get filename, absolute path, and the hashes.
                filename = os.path.basename(file_location)
                file_abs = os.path.abspath(file_location)
                file_hashes = cryptor.hashes(file_location)

                # Get the file reputation from TIE using the hashes (MD5, SHA1, SHA256)
                reps = tie.get_file_rep(file_hashes)

                print "\n\n> File: " + file_abs

                ''' Rep providers: 1 == GTI, 3 = Enterprise, 5 = ATD
                If there is no result for the reputation provider, set it to 0.
                The "trustLevel" is an int that corresponds to a key in the rep_descriptions dict.
                '''
                if 1 in reps:
                    gti_trust = reps[1]["trustLevel"]
                else:
                    gti_trust = 0

                if 3 in reps:
                    tie_trust = reps[3]["trustLevel"]
                else:
                    tie_trust = 0

                if 5 in reps:
                    atd_trust = reps[5]["trustLevel"]
                else:
                    atd_trust = 0


                def print_reps(gti_trust, tie_trust, atd_trust, file_hashes):
                    """Print the hashes on screen with the reputation from our three providers"""
                    print dumps(file_hashes, sort_keys=True, indent=4, separators=(',', ': '))
                    print "> GTI Reputation: " + str(gti_trust) + ":" + self.rep_descriptions[gti_trust]
                    print "> TIE Reputation: " + str(tie_trust) + ":" + self.rep_descriptions[tie_trust]
                    print "> ATD Reputation: " + str(atd_trust) + ":" + self.rep_descriptions[atd_trust]

                def good_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, source):
                    """If the file is good then print the information with no further action"""
                    print_reps(gti_trust, tie_trust, atd_trust, file_hashes)
                    print "> File Passed based on " + source + " reputation: " + file_abs

                def bad_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, source):
                    """If the file is bad then print the information and proceed to quarantine the file"""
                    print_reps(gti_trust, tie_trust, atd_trust, file_hashes)
                    print "> QUARANTINING MALICIOUS FILE based on " + source + " reputation: " + file_abs
                    # Quarantine the file because ATD result is positive for malware
                    Quarantine.move_file(file_location)
                    readme = open(file_location + "_READ_ME.txt", "w")
                    readme.write("Your file has been QUARANTINED due to suspected MALWARE.\n\n"
                                 "Please check with your administrator for next steps.\n\n")
                    readme.close()
                    print "\n> MALICIOUS FILE DETECTED: File has been quarantined."

                def unknown_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs):
                    """If the file is unknown to our reputation providers then take action
                    
                    First print the information,
                    Secondly upload the file to ATD for analysis,
                    The file must be locked after uploading to ATD
                    Once the result comes back from ATD then update TIE with the result
                    """
                    print_reps(gti_trust, tie_trust, atd_trust, file_hashes)
                    print "> Unknown file reputation. Sending to ATD for analysis: " + file_abs

                    # Upload the file to ATD
                    analysis = ATD.uploadtoatd(file_location)
                    taskid = analysis["taskid"]

                    print "\n> File \"" + file_location + "\" has been sent to ATD for analysis and has been " \
                          "assigned the Task ID of " + str(taskid)

                    # The file has been uploaded to ATD so we are now able to lock the file
                    cryptor.lock_file(file_location)

                    # Get the first status of the current analysis
                    status = ATD.taskstatus(taskid)
                    print "> Current status of Task " + str(taskid) + ": \"" + self.statuses[status] + "\" ("\
                          + str(status) + ")"

                    # Failed statuses or status out of range
                    if status < -1 or status == 0 or status > 4:
                        print "> Task failed due to unknown error"
                        status = 0

                    # Begin a counter for the timeout check
                    counter = 0

                    # If the status does not indicate success or failure (i.e. it is queued or being analysed,
                    # or some unforeseen error) Timeout set to 12.5 mins (50 ticks * 15 secs)
                    while status not in [-1, 1, 2] and counter < 25:

                        # Poll for current status every 15 seconds
                        sleep(15)
                        status = ATD.taskstatus(taskid)
                        print "> Current status of Task " + str(taskid) + ": \"" + self.statuses[status] \
                              + "\" (" + str(status) + ")"

                        # Increase timeout counter unless file is just queued
                        # (we don't want to timeout queue prematurely)
                        if status != 4:
                            counter = counter + 1

                        if counter == 50:
                            print "> Task TIMEOUT"


                    # Either task completed, failed, or loop broke due to timeout.
                    print "> Task Finished (status: " + self.statuses[status] + " [" + str(status) + "])"

                    # Get the result using the file's MD5 rather than checking the task id result
                    # MD5 gives more accurate results if the file was already blacklisted or result is static analysis
                    result = ATD.atd_md5(file_hashes["md5"])
                    severity = result["severity"]

                    print "> Analysis result: " + self.atd_descriptions[severity] + " [" + str(severity) + "]"


                    if severity in self.atdsafe:
                        # Unlock the file because ATD result is negative for malware
                        cryptor.unlock_file(file_location)

                    elif severity in self.atdquar:
                        # Quarantine the file because ATD result is positive for malware
            #            cryptor.unlock_file(file_location)
                        Quarantine.move_file(file_location + ".lock")
                        readme = open(file_location + "_READ_ME.txt", "w")
                        readme.write("Your file has been QUARANTINED due to suspected MALWARE.\n\n"
                                     "Please check with your administrator for next steps.\n\n")
                        readme.close()
                        print "\n> MALICIOUS FILE DETECTED: File has been quarantined."

                    else:
                        # If there's an unforeseen error then leave the file locked and call for help
                        print "\n> ERROR OCCURRED: File will remain locked. Please contact your administrator"


                    '''Update the TIE reputation with the result from ATD. 
                    In order to do this we need to compare the ATD severity to the TIE/GTI reputation levels.
                    
                    ***IT IS CRITICALLY IMPORTANT THAT TIE GETS UPDATED WITH THE ATD RESULT***
                    
                    If TIE isn't updated with the ATD result then the same file will be analysed over and over again
                    whenever it gets decrypted because that is a newly written file and triggers the event listener.
                    
                    tie_sev is simply a mapping of ATD to TIE/GTI
                    set_file_rep() is the method for updating TIE. If this returns False then FS2ATD exits.
                    '''
                    tie_sev = self.reps_map[severity]
                    if tie.set_file_rep(file_hashes, filename, tie_sev):
                        print "> File Reputation in TIE changed to : " + self.rep_descriptions[tie_sev]
                    else:
                        # FS2ATD has to exit if it cannot set reputation otherwise will loop sending files to ATD
                        print "> Error setting reputation. FS2ATD will now exit."
                        exit()


                '''First off, we want to trust TIE more than other reputations sources so that the admin has final
                say on which files are allowed and are not allowed. 
                '''
                if tie_trust in self.rep2pass:
                    # We begin by allowing all good files according to TIE.
                    good_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, "TIE")

                elif tie_trust in self.rep2quar:
                    # Then blocking all bad files according to TIE.
                    bad_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, "TIE")

                elif gti_trust in self.rep2pass:
                    # Then allowing files whitelisted in GTI.
                    good_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, "GTI")

                elif gti_trust in self.rep2quar:
                    # And then blocking all GTI blacklisted files.
                    bad_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, "GTI")

                elif atd_trust in self.rep2pass:
                    # Then we trust which files ATD says are OK.
                    good_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, "ATD")

                elif atd_trust in self.rep2quar:
                    # And quarantine the files ATD convicts as malicious.
                    bad_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs, "ATD")

                else:
                    # Finally if a file is "Unknown" to any of our reputations sources we send it to ATD.
                    unknown_file(gti_trust, tie_trust, atd_trust, file_hashes, file_abs)

            else:
                # If the file detected by the event listener is not a file type that we are interested in then we
                # just return out of the method back to __main__.
                return


if __name__ == "__main__":
    """From __main__  take the parameter of which directory to monitor and begin listening for events in that dir.
    
    The path of the directory to be monitored is passed from a command line argument but if no path is specified it 
    uses the directory that the script is run from i.e. .\<file>. The script monitors recursively (nested directories).
    To hardcode a path, replace the value of the path variable with a string of the hardcoded path.
    """
    path = sys.argv[1] if len(sys.argv) > 1 else '.'

    print "\nFS2ATD - monitoring path: " + os.path.abspath(path) + "\n"

    ATD = ATD()
    cryptor = Encrypt()
    tie = TIE()

    # Watchdog API code: creates our event listener to detect events in one second intervals.
    event_handler = Event()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
