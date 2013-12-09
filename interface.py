from __future__ import print_function
import requests
import sys
try:
    import json
except ImportError:
    import simplejson as json

"""
"""
__version__ = "0.4.0"
__author__ = "Michael Hileman"

### To-Do: ###
# maybe getJSON should handle list and single dict returns
# getXmlElement() - Bring NS map into interface
#  e.g., getXMLElement("xnat:scanid") returns text of element


class HcpInterface(object):
    def __init__(self, url, username, password, project=None):
        self.url = url
        self.project = project
        self.username = username
        self.password = password
        self.subject_label = None
        self.session_label = None
        self.scan_id = None
        self.__sessionInit(username, password)
        # TODO - Really need a password conf option since in GitHub

    def __sessionInit(self, username, password):
        self.session = requests.Session()
        self.session.auth = (username, password)

        if 'humanconnectome.org' in self.url:
            self.session.verify = True
        else:
            self.session.verify = False

        # Check for a successful login
        r = self.session.get(self.url + '/REST/version')
        if not r.ok:
            print("Login attempt failed.")
            sys.exit(-1)

    def getJson(self, uri):
        """ (str) --> dict
        Takes a REST URI and returns a list of json object as a dictionary.
        """
        # Make format explicit if not already
        if 'format=json' not in uri:
            if '?' in uri:
                uri += '&format=json'
            else:
                uri += '?format=json'

        r = self.session.get(self.url + uri)
        #print(r.text)
        if r.ok:
            return r.json().get('ResultSet').get('Result')
        else:
            print("++ JSON request failed: " + str(r.status_code))
            print("Attempted: " + self.url+uri)
            # return False
            sys.exit(-1)

    def getJSON(self, uri):
        """ (str) --> dict
        Takes a REST URI and returns a list of json object as a dictionary.
        """
        print("getJSON Deprecated!!!")
        r = self.session.get(self.url + uri)
        print(r.text)
        if r.ok:
            return r.json().get('ResultSet').get('Result')
        else:
            print("++ JSON request failed: " + str(r.status_code))
            print("Attempted: " + self.url+uri)
            # return False
            sys.exit(-1)

    def getXML(self, uri):
        """ (str) --> xml
        """
        formatString = '&format=xml' if '?' in uri else '?format=xml'
        r = self.session.get(self.url + uri + formatString)
        if r.ok:
            return r.text[:-1]
        else:
            print("++ XML request failed: " + str(r.status_code))
            print("++ Requested document: " + self.url + uri)
            #sys.exit(-1)

    def getResponse(self, uri):
        """
        Returns the request object
        """
        return self.session.get(self.url + uri)

    def getFile(self, uri, f):
        """ (str, str) --> file [create file handle??]
        """
        if not (uri and f):
            print("You must specifiy a URI and file name")
            return

        print("Downloading from " + self.url + "...")
        print(uri + " --> " + f)

        with open(f, 'wb') as handle:
            #r = self.session.get(self.url+uri, prefetch=True)
            r = self.session.get(self.url+uri, stream=True)
            for block in r.iter_content(1024):
                if not block:
                    break
                handle.write(block)

    def getSubjectXml(self):
        if not self.subject_label:
            msg = "No subject specified. You must set the object's subject before calling."
            #raise InstanceVariableUnsetError(msg, self)

    def getSubjectJson(self):
        if not self.subject_label:
            print("No subject specified. You must set the object's subject and session before calling.")

    def getSessionXml(self):
        if not (self.subject_label and self.session_label):
            print("No subject or session defined.\nYou must set the subject and session instance variables.")

    def getSessionJson(self):
        if not (self.subject_label and self.session_label):
            print("No subject specified. You must set the object's subject xxx before calling.")

    def getScanXml(self, session_label, scan_id):
        """
        Assumes subject is the value of session_label.split('_')[0]
        """
        pass

    def putRequest(self, uri, f=None):
        """ (str, [str]) --> None
        Takes a REST URI and optional file and makes a PUT request.
        If a filename is passed, tries to upload the file.
        """
        if f:
            files = {'file': open(f, 'rb')}
            r = self.session.put(self.url+uri, files=files)
            if r.ok:
                print("PUT successful")
                print(f + " --> " + self.url)
            else:
                print("++ PUT Request FAILED for " + uri)
                print("++ Status: " + str(r.status_code))
        else:
            r = self.session.put(self.url+uri)
            if r.ok:
                print("PUT successful for " + uri)
                return r
            else:
                print("++ PUT request FAILED for " + uri)
                print("++ Status: " + str(r.status_code))

    def putSessionXml(self, xml, session_label):
        url = self.url+'/REST/projects/%s/subjects/%s/experiments/%s?xsiType=xnat:mrSessionData' % \
                   (self.project, session_label.split('_')[0], session_label)
        #print(xml)
        print(url)
        hdrs = {'Content-Type': 'text/xml'}

        r = self.session.put(url, data=xml, headers=hdrs)
        print(r.text)
        print(r.status_code)

    def deleteRequest(self, uri):
        """ (str) --> None
        Tries to delete the resouce specified by the uri
        """
        r = self.session.delete(self.url+uri)
        if r.ok:
            print("DELETE successful for " + uri)
        else:
            print("++ DELETE request FAILED for " + self.url+uri)
            print("++ Status: " + str(r.status_code))


if __name__ == "__main__":

    """ Instanciation Tests """
    intradb = HcpInterface('https://intradb.humanconnectome.org', 'mhileman', 'hcp@XNAT!', 'HCP_Phase2')
    cdb = HcpInterface('https://db.humanconnectome.org', 'admin', 'hcpAdmiN181')
    print("Intradb:\nURL: %s \nProject: %s" % (intradb.url, intradb.project))
    print("Connectomedb:\nURL: " + cdb.url)

    """ Get some stuff """
    print("Getting Json object for projects on " + cdb.url)
    jsonobj = cdb.getJSON('/REST/projects')
    print("Getting Xml for 100307_strc on " + intradb.url)
    xml = intradb.getXML('/REST/projects/'+intradb.project+'/subjects/100307/experiments/100307_strc/scans/10')
    #print("\nJSON object - Projects:")
    #print(jsonobj)
    #print("\nXML object - 100307 subject info:")
    #print(xml)
    print("Done")
