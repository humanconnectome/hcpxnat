from __future__ import print_function
from lxml import etree
import requests
import sys
try:
    import json
except ImportError:
    import simplejson as json

"""
"""
__version__ = "0.5.0"
__author__ = "Michael Hileman"

### To-Do: ###
# maybe getJson should handle list and single dict returns

# Xml Namespace Mappings
NSMAP = {'xnat': 'http://nrg.wustl.edu/xnat', 'xdat': 'http://nrg.wustl.edu/xdat',
                 'cat': 'http://nrg.wustl.edu/catalog', 'nt': 'http://nrg.wustl.edu/nt'}


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

############## Json Methods ##############
    def getJson(self, uri):
        """ (str) --> list
        Takes a REST URI and returns a list of Json objects (python dicts).
        """
        # Make format explicit if not already
        if 'format' not in uri:
            formatString = '&format=json' if '?' in uri else '?format=json'

        #print(self.url + uri + formatString)
        r = self.session.get(self.url + uri + formatString)
        #print(r.text)
        if r.ok:
            return r.json().get('ResultSet').get('Result')
        else:
            print("++ JSON request failed: " + str(r.status_code))
            print("Attempted: " + self.url+uri)
            # return False
            sys.exit(-1)

    def getSubjectJson(self):
        if not self.subject_label:
            print("No subject specified. You must set the object's subject and session before calling.")

    def getSessionJson(self):
        if not (self.subject_label and self.session_label):
            print("No subject specified. You must set the object's subject xxx before calling.")

    def getSubjectSessions(self):
        pass

    def getProjectSessions(self):
        """ () --> dict
        """
        if not self.project:
            print("Project must be specified for interface object")
            sys.exit(-1)
        uri = self.url + '/REST/experiments?xsiType=xnat:mrSessionData&project=' + self.project

        r = self.session.get(uri)
        if r.ok:
            return r.json().get('ResultSet').get('Result')
        else:
            print("++ Session request failed for project " + self.project)

#####################################

############## Xml Methods ##############
    def getXml(self, uri):
        """ (str) --> xml
        Returns utf-8 encoded string of the Xml
        """
        if 'format' not in uri:
            formatString = '&format=xml' if '?' in uri else '?format=xml'

        r = self.session.get(self.url + uri + formatString)
        if r.ok:
            return r.text[:-1].encode('utf8')
        else:
            print("++ XML request failed: " + str(r.status_code))
            print("++ Requested document: " + self.url + uri)

    def getSubjectXml(self):
        if not self.subject_label:
            msg = "No subject specified. You must set the object's subject before calling."
            #raise InstanceVariableUnsetError(msg, self)

    def getSessionXml(self):
        if not (self.subject_label and self.session_label):
            print("No subject or session defined.\nYou must set the subject and session instance variables.")

    def getScanXml(self):
        """
        """
        pass

    def getScanXmlElement(self, element):
        """ (str) --> str
        Returns scan element as a string
        Uses Namespace mapping defined in NSMAP
        """
        if not (self.subject_label and self.session_label and self.scan_id):
            print("Subject, Session, and ScanId must be set for interface object")
            return
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans/%s' % \
                (self.project, self.subject_label, self.session_label, self.scan_id)
        xml = self.getXml(uri).encode('utf8')
        et = etree.fromstring(xml)

        try:
            elem = et.find(element, NSMAP).text
        except AttributeError:
            print(element + " could not be found for " + uri)
        else:
            return elem

    # TODO - Refactor
    def putSessionXml(self, xml, session_label):
        url = self.url+'/REST/projects/%s/subjects/%s/experiments/%s?xsiType=xnat:mrSessionData' % \
                   (self.project, session_label.split('_')[0], session_label)
        #print(xml)
        print(url)
        hdrs = {'Content-Type': 'text/xml'}

        r = self.session.put(url, data=xml, headers=hdrs)
        print(r.text)
        print(r.status_code)

#####################################

############# General Methods #############
    def getResponse(self, uri):
        """
        Returns a request object for the URI
        """
        r = self.session.get(self.url + uri)
        if r.ok:
            return r
        else:
            print("++ Request failed: " + str(r.status_code))
            print("++ Requested document: " + self.url + uri)

    def getHeader(self, uri, attr):
        """
        Returns only the headers for a request and ignores the body
        """
        r = self.session.get(self.url + uri, stream=True)
        if r.ok and r.headers[attr]:
            return r.headers[attr]
        else:
            print("++ Request failed: " + str(r.status_code))
            print("++ Requested headers for: " + self.url + uri)

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
#####################################

########### DEPRECATED Methods ###########
    def getJSON(self, uri):
        """ (str) --> dict
        Takes a REST URI and returns a list of json object as a dictionary.
        """
        print("getJSON Deprecated. Use getJson()")
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
        print("getXML Deprecated. Use getXml().")
        formatString = '&format=xml' if '?' in uri else '?format=xml'
        r = self.session.get(self.url + uri + formatString)
        if r.ok:
            return r.text[:-1]
        else:
            print("++ XML request failed: " + str(r.status_code))
            print("++ Requested document: " + self.url + uri)
            #sys.exit(-1)
#####################################


if __name__ == "__main__":

    """ Instantiation Tests """
    idb = HcpInterface('https://intradb.humanconnectome.org', 'mhileman', 'hcp@XNAT!', 'HCP_Phase2')
    cdb = HcpInterface('https://db.humanconnectome.org', 'admin', 'hcpAdmiN181')
    print("Intradb:\nURL: %s \nProject: %s" % (idb.url, idb.project))
    print("Connectomedb:\nURL: " + cdb.url)

    # TODO - Add failures to tests to see how they're handled
    """ Get some stuff """
    # PASS
    print("Getting Json object for projects on " + cdb.url)
    jsonobj = cdb.getJson('/REST/projects')

    # PASS
    print("Getting Xml by URI on " + idb.url)
    xml = idb.getXml('/REST/projects/'+idb.project+'/subjects/100307/experiments/100307_strc/scans/10')

    # PASS
    print("Getting Xml scan element on " + idb.url)
    idb.subject_label = '100307'
    idb.session_label = '100307_strc'
    idb.scan_id = '19'
    dbScanID = idb.getScanXmlElement('xnat:dbID')
    print("xnat:dbID for %s, scan %s --> %s" % (idb.session_label, idb.scan_id, dbScanID))

    # PASS
    print("Getting Html header element on " + idb.url)
    r = idb.getResponse('/REST/projects/HCP_Phase2/subjects/100307/experiments/100307_strc/scans/11/resources/NIFTI')
    print("Date header: " + r.headers['date'])

    #print("\nJSON object - Projects:")
    #print(jsonobj)
    #print("\nXML object - 100307 subject info:")
    #print(xml)
    print("Done")
