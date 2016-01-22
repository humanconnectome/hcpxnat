from __future__ import print_function
from shutil import copy as fileCopy
from lxml import etree
import ConfigParser
import requests
import sys
import os
import re

"""
"""
__version__ = "0.9.4"
__author__ = "Michael Hileman"

requests.packages.urllib3.disable_warnings()

### To-Do: ###
# Return messages instead of printing success/failure

# Xml Namespace Mappings
NSMAP = {'xnat': 'http://nrg.wustl.edu/xnat',
         'xdat': 'http://nrg.wustl.edu/xdat',
         'cat': 'http://nrg.wustl.edu/catalog',
         'nt': 'http://nrg.wustl.edu/nt',
         'hcpvisit': 'http://nrg.wustl.edu/hcpvisit',
         'hcp': 'http://nrg.wustl.edu/hcp'}


class HcpInterface(object):
    def __init__(self, url=None, username=None, password=None,
                 project=None, config=None):
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
        self.resource_label = None
        self.message = None
        self.success = True
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
        self.get('/REST/version')

########################### Request Method Wrappers ###########################
    def get(self, uri, **kwargs):
        # print('self.url+uri={}'.format(self.url+uri))
        r = self.session.get(self.url+uri, **kwargs)
        try:
            r.raise_for_status()
        except Exception as e:
            print("GET failed for {}".format(uri))
            if kwargs:
                print("Keyword args: {}".format(kwargs))
            raise e
        return r

    def put(self, uri, **kwargs):
        """ (str, [str]) --> None
        Takes a REST URI and optional file and makes a PUT request.
        If a filename is passed, tries to upload the file.
        """
        r = self.session.put(self.url+uri, **kwargs)
        try:
            r.raise_for_status()
        except Exception as e:
            print("PUT failed for uri {}".format(uri))
            if kwargs:
                print("Keyword args: {}".format(kwargs))
            raise e
        print("PUT successful for " + uri)

        return r

    def post(self, uri, **kwargs):
        """ (str, [str]) --> None
        Takes a REST URI and optional file and makes a POST request.
        If a filename is passed, tries to upload the file.
        """
        r = self.session.post(self.url+uri, **kwargs)
        try:
            r.raise_for_status()
        except Exception as e:
            print("POST failed for uri {}".format(uri))
            if kwargs:
                print("Keyword args: {}".format(kwargs))
            raise e
        print("POST successful for " + uri)

        # return r

    def delete(self, uri, **kwargs):
        """ (str) --> None
        Tries to delete the resource specified by the uri
        """
        r = self.session.delete(self.url+uri, **kwargs)
        try:
            r.raise_for_status()
        except Exception as e:
            print("DELETE request failed for uri {}".format(uri))
            if kwargs:
                print("Keyword args: {}".format(kwargs))
            raise e
        print("DELETE successful for " + uri)

################################# Json Methods ################################
    def getJson(self, uri):
        """ (str) --> list
        Takes a REST URI and returns a list of Json objects (python dicts).
        """
        uri = self.addQuery(uri, format='json')

        r = self.get(uri)
        js = r.json()
        if 'ResultSet' in js and 'Result' in js['ResultSet']:
            return js['ResultSet']['Result']
        elif 'items' in js:
            return js['items']
        else:
            return js

    # TODO
    def getSubjectJson(self):
        if not self.subject_label:
            print("No subject specified. You must set the object's subject " +
                  "and session before calling.")

    # TODO
    def getSessionJson(self):
        if not (self.subject_label and self.session_label):
            print("No subject specified. You must set the object's " +
                  "subject xxx before calling.")

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
            uri = '/REST/projects/' + project + \
                '/experiments?xsiType=xnat:mrSessionData'
        else:
            uri = '/REST/experiments?xsiType=xnat:mrSessionData'
        return self.getJson(uri)

    def getExperiments(self, **kwargs):
        # if xsi and project:
        #     uri = '/REST/experiments?xsiType=' + xsi + \
        #         '&project=' + self.project
        # elif xsi:
        #     uri = uri = '/REST/experiments?xsiType=' + xsi
        # else:
        #     uri =
        return self.getJson(self.addQuery('/REST/experiments', **kwargs))

    def getSubjectSessions(self):
        """ () --> dict
        """
        if not self.project and not self.subject_label:
            sys.exit("Project and subject must be set for interface object")
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

    def getScanResources(self):
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
            '/scans/%s/resources' % \
            (self.project, self.subject_label,
             self.session_label, self.scan_id)
        return self.getJson(uri)

    def getScanResourceDate(self):
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
              '/scans/%s/resources/%s' % \
              (self.project, self.subject_label, self.session_label,
               self.scan_id, self.resource_label)
        return self.getXml(uri)
        # return uri

    def getResourceFiles(self):
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
            '/scans/%s/resources/%s/files' % \
            (self.project, self.subject_label, self.session_label,
             self.scan_id, self.resource_label)
        return self.getJson(uri)

################################# Xml Methods #################################
    def getXml(self, uri):
        """ (str) --> xml
        Returns utf-8 encoded string of the Xml
        """
        uri = self.addQuery(uri, format='xml')

        r = self.get(uri)
        return r.text.strip().encode('utf8')

    # TODO
    def getSubjectXml(self):
        if not self.subject_label:
            msg = "No subject specified. You must set the object's " + \
                  "subject before calling."
            # raise InstanceVariableUnsetError(msg, self)

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
            print("Subject, Session, and ScanId must be set for calling object")
            return
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/scans/%s' % \
            (self.project, self.subject_label,
             self.session_label, self.scan_id)

        return self.getXmlElement(element, uri)

    def getSubjectXmlElement(self, element):
        """ (str) --> str
        Returns Subject element as a string
        """
        if not self.subject_label:
            print("Subject must be set for interface object")
            return
        uri = '/REST/projects/%s/subjects/%s' % \
            (self.project, self.subject_label)

        return self.getXmlElement(element, uri)

    def getSessionXmlElement(self, element):
        """ (str) --> str
        Returns Session element as a string
        """
        if not (self.subject_label and self.session_label):
            print("Subject and Session must be set for calling object")
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
        et = self.getXmlTree(uri)
        try:
            elem = et.find(element, NSMAP).text
        except AttributeError:
            print(element + " could not be found for " + uri)
            self.success = False
            return None
        else:
            return elem

    def getXmlTree(self, uri):
        return etree.fromstring(self.getXml(uri))

    def putXml(self, uri, xml):
        hdrs = {'Content-Type': 'text/xml'}
        self.put(uri, data=xml, headers=hdrs)

    # TODO - Refactor
    def putSessionXml(self, session_label, xml):
        subject_label = self.getSessionSubject()
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
            '?xsiType=xnat:mrSessionData' % \
            (self.project, subject_label, session_label)
        hdrs = {'Content-Type': 'text/xml'}

        r = self.put(uri, data=xml, headers=hdrs)
        print(r.text)
        print(r.status_code)

############################# Convenience Methods #############################
    def getSessionSubject(self):
        """ () --> str
        Returns the subject label for the object's session label
        """
        uri = '/REST/projects/%s/experiments/%s' % \
            (self.project, self.session_label)
        json = self.getJson(uri)

        for item in json:
            try:
                # Sometimes the Subject label is the dcmPatientName, 
                # sometimes the dcmPatientId
                subject_label = item.get('data_fields').get('dcmPatientName')
                if subject_label and not self.subjectExists(subject_label):
                    subject_label = item.get('data_fields').get('dcmPatientId')
            except:
                print("Not here")

        if subject_label:
            return subject_label
        else:
            print("Couldn't get subject label for " + self.session_label)

    def getSessionId(self):
        """ () --> str
        Returns the session ID for the object
        """
        uri = '/REST/projects/%s/experiments/%s' % \
            (self.project, self.session_label)
        json = self.getJson(uri)

        for item in json:
            try:
                sessionId = item.get('data_fields').get('id')
            except:
                print("Session ID not in this item")
        if sessionId:
            return sessionId
        else:
            print("Couldn't get session ID for " + self.session_label)

    def getSessionAssessors(self):
        """ () --> dict
        Returns all assessors for a session
        """
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/assessors' % \
            (self.project, self.subject_label, self.session_label)
        print(self.url + uri)
        return self.getJson(uri)

    def getSubjectId(self):
        """ ()--> str
        Returns the subject ID for the object's subject_label
        """
        uri = '/REST/projects/%s/subjects/%s' % \
            (self.project, self.subject_label)
        json = self.getJson(uri)

        try:
            subjectID = json[0].get('data_fields').get('ID')
        except AttributeError:
            print("AttributeError: Couldn't get subject id for " +
                  self.subject_label)
        else:
            return subjectID

    def getSessionScanIds(self):
        """ () --> list
        Returns a list of scan numbers for the object's session_label
        """

        scanIds = [scan.get('ID') for scan in self.getSessionScans()]

        if not scanIds or len(scanIds) == 0:
            print("Did not get any scan IDs for " + self.session_label)

        return scanIds

    def projectExists(self, proj=None):
        if proj:
            label = proj
        elif self.project:
            label = self.project
        else:
            print("Either the object's project must be set or the project " +
                  "parameter passed")
            return

        uri = '/REST/projects/{p}'.format(p=label)

        try:
            self.get(uri)
        except:
            return False
        return True

    def subjectExists(self, sub=None):
        if sub:
            label = sub
        elif self.subject_label:
            label = self.subject_label
        else:
            print("Either the object's subject_label must be set or the " + \
                  "sub parameter passed.")

        uri = '/REST/projects/%s/subjects/%s?format=json' % \
            (self.project, label)

        try:
            self.get(uri)
        except:
            return False
        return True

    def experimentExists(self, exp=None):
        if exp:
            label = exp
        elif self.experiment_label:
            label = self.experiment_label
        elif self.session_label:
            label = self.session_label
        else:
            print("Either the object's session_label or experiment_label " +
                  "must be set or the sub parameter passed.")

        uri = '/REST/projects/%s/experiments/%s?format=json' % \
            (self.project, label)
        try:
            self.get(uri)
        except:
            return False
        return True

    def createScanResource(self, resource):
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
            '/scans/%s/resources/%s' % \
            (self.project, self.subject_label, self.session_label,
             self.scan_id, resource)

        self.putRequest(uri)

    def putScanResource(self, f):
        fname = os.path.basename(f)
        uri = '/REST/projects/%s/subjects/%s/experiments/' \
            '%s/scans/%s/resources/%s/files/%s' % \
            (self.project, self.subject_label, self.session_label,
             self.scan_id, self.resource_label, fname)

        self.putRequest(uri, f)

    def getUsers(self, project=None):
        if project:
            uri = '/REST/projects/%s/users' % (project)
        else:
            uri = '/REST/users'
        return self.getJson(uri)

    # TODO
    def deleteProject(self):
        pass

    # TODO
    def deleteSubject(self):
        pass

    # TODO
    def deleteExperiment(self):
        pass

    def deleteSessionAssessor(self, label):
        uri = '/REST/projects/%s/subjects/%s/experiments/%s/assessors/%s' % \
            (self.project, self.subject_label, self.session_label, label)
        self.deleteRequest(uri)

################################ General Methods ##############################
    def getResponse(self, uri):
        return self.get(uri)

    def getHeaderField(self, uri, attr):
        """
        Returns only the headers for a request and ignores the body
        """
        r = self.get(uri, stream=True)
        if attr not in r.headers:
            print("++ Request OK, but attribute " + attr + " does not exist")
        return r.headers.get(attr,None)
        # if r.ok and r.headers[attr]:
        #     return r.headers[attr]
        # elif r.ok and not r.headers[attr]:
        #     print("++ Request OK, but attribute " + attr + " does not exist")
        # else:
        #     print("++ Request failed: " + str(r.status_code))
        #     print("++ Requested headers for: " + self.url + uri)

    def getFiles(self, uri, useAbsPath=False, symlink=False):
        if '/files' not in uri:
            print('URI {} does not point to any files.'.format(uri))
            return

        uri = self.stripQueries(uri,'locator') # We need to control when this gets added

        ##########
        # Get the list of file resource dicts
        listOfFileDicts = self.getJson(self.addQuery(uri,format="json"))

        ##########
        # The 'Name' field does not maintain the directory structure present in XNAT.
        # Make a 'localPath' that does.
        for fileDict in listOfFileDicts:
            localPath = '/files/'.join( fileDict['URI'].split('/files/')[1:] )
            if not localPath:
                localPath = fileDict['Name']
            fileDict['localPath'] = localPath

            if not os.path.exists(os.path.dirname(localPath)):
                os.makedirs(os.path.dirname(localPath))

        if not useAbsPath:
            return self.getFilesByDownload(listOfFileDicts)
        else:
            listOfFileDictsWithAbsPath = \
                self.getJson(self.addQuery(uri, format="json",
                             locator="absolutePath"))

            ##########
            # Sanity checks
            if not (listOfFileDicts[0].get('URI') and
                    listOfFileDicts[0].get('localPath')):
                print('++ Did not find "URI" or "localPath" for uri {}.'
                      .format(uri))
                return
            if 'absolutePath' not in listOfFileDictsWithAbsPath[0]:
                print('++ Could not get absolutePath for uri {}.'.format(uri))
                print('++ Attempting to download.')
                return self.getFilesByDownload(listOfFileDicts)

            ##########
            # Set the method: copy or symlink
            if symlink:
                print('++ Attempting to symlink files for uri {}.'.format(uri))
                copyOrLinkMethod = os.symlink
                msg = "+++ Made symlink "
            else:
                print('++ Attempting to copy files for uri {}.'.format(uri))
                copyOrLinkMethod = fileCopy
                msg = "+++ Copied "

            ##########
            # Iterate through the files and use the method to get them
            for fileDict, fileDictWithAbsPath in zip(listOfFileDicts, listOfFileDictsWithAbsPath):
                absPath = fileDictWithAbsPath['absolutePath']
                localPath = fileDict['localPath']
                if os.access(absPath, os.R_OK):
                    copyOrLinkMethod(absPath, localPath)
                    print(msg + "{} --> {}".format(absPath, localPath))
                else:
                    print('Could not access {}.'
                          .format(absPath, fileDict['URI']))
                    self.getFile(fileDict['URI'], localPath)

            print("All done!")

    def getFilesByDownload(self, listOfFileDicts):
        for fileDict in listOfFileDicts:
            if 'URI' not in fileDict:
                print('Could not download. No URI.')
                return
            else:
                uri = fileDict['URI']
                localPath = fileDict.get('localPath')
                if not localPath:
                    localPath = fileDict.get('Name')

                self.getFile(uri, localPath)

    def getFile(self, uri, f):
        """ (str, str) --> file [create file handle??]
        """
        if not (uri and f):
            print("You must specifiy a URI and file name")
            return

        print("Downloading from " + self.url + "...")
        print(uri + " --> " + f)

        with open(f, 'wb') as handle:
            # r = self.session.get(self.url+uri, prefetch=True)
            r = self.get(uri, stream=True)
            for block in r.iter_content(1024):
                if not block:
                    break
                handle.write(block)
        print("Done")

    def putFile(self, uri, f):
        """
        Puts file f to specified uri
        """
        files = {'file': open(f, 'rb')}
        self.put(uri, files=files)
        print(f + " --> " + self.url)

    def putRequest(self, uri, f=None):
        """ (str, [str]) --> requests.Response
        Takes a REST URI and optional file and makes a PUT request.
        If a filename is passed, tries to upload the file.
        """
        if f:
            files = {'file': open(f, 'rb')}
            r = self.put(uri, files=files)
            print(f + " --> " + self.url)
        else:
            r = self.put(uri)
        return r

    def deleteRequest(self, uri):
        return self.delete(uri)

    def addQuery(self, uri, **kwargs):
        if kwargs == {} or all([val is None for val in kwargs.values()]):
            return uri
        queries = []
        for (argName, argVal) in kwargs.iteritems():
            if argVal is None:
                continue
            query = argName+'='+argVal
            if argName not in uri or query not in uri:
                queries.append(query)
            else:
                m = re.search(r'{}=(?P<val>[^&]*)(&.*)?$'.format(argName), uri)
                if m:
                    uri.replace(m.group('val'), argVal)
                else:
                    pass
        if len(queries) == 0:
            return uri
        querySep = '?' if '?' not in uri else '&'
        return uri + querySep + '&'.join(queries)

    def stripQueries(self, uri, *queryKeys):
        if not queryKeys or '?' not in uri:
            return uri.split('?')[0]
        else:
            root, queryStr = uri.split('?')
            queries = [q.split('=') for q in queryStr.split('&')]
            filteredQueries = \
                filter(lambda (k, v): k not in queryKeys, queries)
            return self.addQuery(root, **dict(filteredQueries))

################################### Setters ###################################

    def setSubjectElement(self, xsi, elem, val):
        """ (str, str, str) --> None
        Sets element=value at the subject level
        """
        uri = '/REST/projects/%s/subjects/%s?xsiType=%s&%s/%s=%s' % \
            (self.project, self.subject_label, xsi, xsi, elem, val)
        self.putRequest(uri)

    def setExperimentElement(self, xsi, elem, val):
        """ (str, str, str) --> None
        Sets element=value at the experiment level
        """
        if 'mrSessionData' in xsi:
            self.experiment_label = self.session_label
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
            '?xsiType=%s&%s/%s=%s' % \
            (self.project, self.subject_label, self.experiment_label,
             xsi, xsi, elem, val)
        self.putRequest(uri)

    def setScanElement(self, xsi, elem, val):
        """ (str, str, str) -> None
        Sets element=value at the scan level
        """
        uri = '/REST/projects/%s/subjects/%s/experiments/%s' \
            '/scans/%s?xsiType=%s&%s/%s=%s' % \
            (self.project, self.subject_label, self.session_label,
             self.scan_id, xsi, xsi, elem, val)
        self.putRequest(uri)

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
            # sys.exit(-1)

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
###############################################################################
