from __future__ import print_function
from lxml import etree
import ConfigParser
import requests
import sys
import os

"""
"""
__version__ = "0.8.4"
__author__ = "Michael Hileman"

### To-Do: ###
# Verbose output option

# Xml Namespace Mappings
NSMAP = {'xnat': 'http://nrg.wustl.edu/xnat', 'xdat': 'http://nrg.wustl.edu/xdat',
         'cat': 'http://nrg.wustl.edu/catalog', 'nt': 'http://nrg.wustl.edu/nt',
         'hcpvisit': 'http://nrg.wustl.edu/hcpvisit', 'hcp': 'http://nrg.wustl.edu/hcp'}


class HcpInterface(object):
    def __init__(self, url=None, username=None, password=None, project=None, config=None):
        self.url = url
        self.username = username
        self.password = password
        self.config = config
        self.project = project
        self.subject_label = None
        self.session_label = None
        self.experiment_label = None
        self.experiment_id = None
        self.scan_id = None
        self.scan_resource = None
        self.__sessionInit()

    def __sessionInit(self):
        if self.config:
            cfg = ConfigParser.ConfigParser()
            cfg.read(self.config)
            self.username = cfg.get('auth', 'username')
            self.password = cfg.get('auth', 'password')
            self.url = cfg.get('site', 'hostname')
            self.project = cfg.get('site', 'project')

        self.session = requests.Session()
        self.session.auth = (self.username, self.password)

        if 'humanconnectome.org' in self.url:
            self.session.verify = True
        else:
            self.session.verify = False

        # Check for a successful login
        r = self.session.get(self.url + '/REST/version')
        if not r.ok:
            print("++ Connection Error")
            print("++ Status: " + str(r.status_code))
            sys.exit(-1)

################################# Json Methods ################################
    def getJson(self, uri):
        """ (str) --> list
        Takes a REST URI and returns a list of Json objects (python dicts).
        """
        # Make format explicit if not already
        formatString = ''
        if 'format' not in uri:
            formatString = '&format=json' if '?' in uri else '?format=json'

        #print(self.url + uri + formatString)
        r = self.session.get(self.url + uri + formatString)
        #print(r.text)
        if r.ok:
            try:
                return r.json().get('ResultSet').get('Result')
            except AttributeError:
                try:
                    return r.json().get('items')
                except AttributeError:
                    print("Could not get a 'ResultSet' or 'items' for " + uri)
        else:
            print("++ JSON request failed: " + str(r.status_code))
            print("Attempted: " + self.url+uri)
            # return False
            sys.exit(-1)

    # TODO
    def getSubjectJson(self):
        if not self.subject_label:
            print("No subject specified. You must set the object's subject and session before calling.")

    # TODO
    def getSessionJson(self):
        if not (self.subject_label and self.session_label):
            print("No subject specified. You must set the object's subject xxx before calling.")

    def getSubjects(self, project=None):
        """ () --> dict
        """
        if project:
            uri = '/REST/projects/' + project + '/subjects'
        else:
            uri = '/REST/subjects'

        return self.getJson(uri)

    def getSessions(self, project=None):
        """ (str) --> dict
        Returns all MR Sessions for a given project if specified,
        or all Sessions for the entire system if not.
        """
        if project:
            uri = '/REST/projects/' + project + '/experiments?xsiType=xnat:mrSessionData'
        else:
            uri = '/REST/experiments?xsiType=xnat:mrSessionData'

        return self.getJson(uri)

    def getSubjectSessions(self):
        """ () --> dict
        """
        if not self.project and not self.subject_label:
            print("Project and subject must be set for interface object")
            sys.exit(-1)
        uri = '/REST/experiments?xsiType=xnat:mrSessionData' + \
            '&project=' + self.project + \
            '&subject_label=' + self.subject_label

        return self.getJson(uri)

    def getSessionScans(self):
        """ () --> list
        Returns a list of dicts containing scan data
        """
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans' % \
            (self.project, self.subject_label, self.session_label)
        scans = self.getJson(uri)
        return scans

################################## Xml Methods ################################
    def getXml(self, uri):
        """ (str) --> xml
        Returns utf-8 encoded string of the Xml
        """
        formatString = ''
        if 'format' not in uri:
            formatString = '&format=xml' if '?' in uri else '?format=xml'

        r = self.session.get(self.url + uri + formatString)
        if r.ok:
            return r.text[:-1].encode('utf8')
        else:
            print("++ XML request failed: " + str(r.status_code))
            print("++ Requested document: " + self.url + uri)

    # TODO
    def getSubjectXml(self):
        if not self.subject_label:
            msg = "No subject specified. You must set the object's subject before calling."
            #raise InstanceVariableUnsetError(msg, self)

    # TODO
    def getSessionXml(self):
        if not (self.subject_label and self.session_label):
            print("Subject and session must be set for interface object.")

    # TODO
    def getScanXml(self):
        """
        """
        pass

    def getScanXmlElement(self, element):
        """ (str) --> str
        Returns scan element as a string
        """
        if not (self.subject_label and self.session_label and self.scan_id):
            print("Subject, Session, and ScanId must be set for interface object")
            return
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans/%s' % \
                (self.project, self.subject_label, self.session_label, self.scan_id)

        return self.getXmlElement(element, uri)

    def getSubjectXmlElement(self, element):
        """ (str) --> str
        Returns Subject element as a string
        """
        if not self.subject_label:
            print("Subject must be set for interface object")
            return
        uri = '/REST/projects/%s/subjects/%s' % (self.project, self.subject_label)

        return self.getXmlElement(element, uri)

    def getSessionXmlElement(self, element):
        """ (str) --> str
        Returns Session element as a string
        """
        if not (self.subject_label and self.session_label):
            print("Subject, Session, and ScanId must be set for interface object")
            return
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' % \
                (self.project, self.subject_label, self.session_label)

        return self.getXmlElement(element, uri)

    def getExperimentXmlElement(self, element):
        """ (str) --> str
        Returns Experiment element as a string
        """
        if not self.experiment_id:
            print("Experiment ID must be set for interface object")
            return
        uri = '/REST/experiments/' + self.experiment_id

        return self.getXmlElement(element, uri)

    def getXmlElement(self, element, uri):
        """
        Helper for all Xml Element Getters
        Uses Namespace mapping defined in NSMAP
        """
        xml = self.getXml(uri)
        et = etree.fromstring(xml)
        try:
            elem = et.find(element, NSMAP).text
        except AttributeError:
            print(element + " could not be found for " + uri)
            return None
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

############################## Convenience Methods ############################
    def getSessionSubject(self):
        """ () --> str
        Returns the subject label for the object's sub label or id
        """
        uri = '/REST/projects/%s/experiments/%s' % (self.project, self.session_label)
        json = self.getJson(uri)

        try:
            subject_label = json[2].get('data_fields').get('dcmPatientName')
        except AttributeError:
            print("AttributeError: Couldn't get subject label for " + self.session_label)
        else:
            return subject_label

    def getSessionId(self):
        """ () --> str
        Returns the session ID for the object
        """
        uri = '/REST/projects/%s/experiments/%s' % (self.project, self.session_label)
        json = self.getJson(uri)

        try:
            sessionID = json[1].get('data_fields').get('id')
        except IndexError:
            try:
                sessionID = json[0].get('children')[0].get('items')[0].get('data_fields').get('id')
            except IndexError, AttributeError:
                print("IndexError OR AttributeError: Couldn't get session id for " + self.session_label)
                return None
            else:
                return sessionID
        else:
            return sessionID

    def getSubjectId(self):
        """ ()--> str
        Returns the subject ID for the object's subject_label
        """
        uri = '/REST/projects/%s/subjects/%s' % (self.project, self.subject_label)
        json = self.getJson(uri)

        try:
            subjectID = json[0].get('data_fields').get('ID')
        except AttributeError:
            print("AttributeError: Couldn't get subject id for " + self.subject_label)
        else:
            return subjectID

    def getSessionScanIds(self):
        """ () --> list
        Returns a list of scan numbers for the object's session_label
        """
        scans = self.getSessionScans()
        scanIds = list()

        for scan in scans:
            scanIds.append(scan.get('ID'))

        if not scanIds:
            print("Did not get any scan IDs for " + self.session_label)
        else:
            return scanIds

    def subjectExists(self):
        pass

    def experimentExists(self):
        pass

    def createScanResource(self, resource):
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans/%s/resources/%s' % \
              (self.project, self.subject_label, self.session_label, self.scan_id, resource)

        self.putRequest(uri)

    def putScanResource(self, f):
        fname = os.path.basename(f)
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans/%s/resources/%s/files/%s' % \
              (self.project, self.subject_label, self.session_label, self.scan_id, self.scan_resource, fname)

        self.putRequest(uri, f)

################################ General Methods ##############################
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

    def getHeaderField(self, uri, attr):
        """
        Returns only the headers for a request and ignores the body
        """
        r = self.session.get(self.url + uri, stream=True)
        if r.ok and r.headers[attr]:
            return r.headers[attr]
        elif r.ok and not r.headers[attr]:
            print("++ Request OK, but attribute " + attr + " does not exist")
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

#################################### Setters ##################################

    def setSubjectElement(self, xsi, elem, val):
        """ (str, str, str) --> None
        Sets element=value at the subject level
        """
        uri = '/REST/projects/%s/subjects/%s?xsiType=%s&%s/%s=%s' % \
               (self.project, self.subject_label, xsi, xsi, elem, val)
        self.putRequest(uri)

    def setExperimentElement(self, xsi, elem, val):
        """ (str, str, str) --> None
        Sets element=value at the subject level
        """
        uri = '/REST/projects/%s/subjects/%s/experiments/%s?xsiType=%s&%s/%s=%s' % \
               (self.project, self.subject_label, self.experiment_label, xsi, xsi, elem, val)
        self.putRequest(uri)

    def setScanElement(self, xsi, elem, val):
        """
        """
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans/%s?xsiType=%s&%s/%s=%s' % \
               (self.project, self.subject_label, self.session_label, self.scan_id, xsi, xsi, elem, val)
        print(uri)
        print("Not implemented")


############################### DEPRECATED Methods ############################
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

    def getProjectSessions(self):
        """ () --> dict
        """
        print("getProjectSessions Deprecated. Use getSessions(proj_name).")
        if not self.project:
            print("Project must be specified for interface object")
            sys.exit(-1)
        uri = self.url + '/REST/experiments?xsiType=xnat:mrSessionData' + \
            '&project=' + self.project

        r = self.session.get(uri)
        if r.ok:
            return r.json().get('ResultSet').get('Result')
        else:
            print("++ Session request failed for project " + self.project)
###############################################################################s
