from __future__ import print_function
from datetime import datetime, timedelta
import subprocess as sp
import datetime
import requests
import urllib
import time
import sys
import os
try:
    import json
except ImportError:
    import simplejson as json

### To-Do: ###
# maybe getJSON should handle list and single dict returns
# getXMLElement() - Bring NS map into interface
#  e.g., getXMLElement("xnat:scanid") returns text of element

class HcpInterface(object):
    def __init__(self, url, username, password, project=None):
        self.url = url
        self.project = project
        self.username = username
        self.password = password
        self.__sessionInit(username, password)
        
    def __sessionInit(self, username, password):
        self.session = requests.Session()
        self.session.auth = (username, password)
        if 'humanconnectome.org' in self.url:
            self.session.verify = True
        else:
            self.session.verify = False

    def getJSON(self, uri):
        """ (str) --> dict
        Takes a REST URI and returns a list of json object as a dictionary.
        """
        r = self.session.get(self.url + uri)
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

    def getSubjectXml(self, subject_label):
        pass

    def getSubjectJson(self, subject_label):
        pass

    def getSessionXml(self, session_label):
        """
        Assumes subject is the value of session_label.split('_')[0]
        """
        pass

    def getSessionJson(self, session_label):
        pass

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


class PipelineManager(HcpInterface):
    pass


class ResourceManager(HcpInterface):

    ### SANITY CHECKS ###
    def sanityCheck(self, resource):
        pass

    def __checkEVs(self):
        pass

    def __checkFSFs(self):
        pass
    ### END SANITY CHECKS ###


class Pipeline(object):
    """
    Pipeline operations specific to the Human Connectome Project.
    Usage:
    >>> pipe_object = Pipeline('http://example.com', username, pass)
    >>> pipe_object.verify('facemask', days_ago=7)
    >>> pipe_object.report(console=True, email=False)
    --> Outputs facemask report for the past week to the console
    >>> pipe_object.process('dcm2nii', ['123_strc', '456_fnca'])
    --> Runs dicom-to-nifti on list of sessions, pipeline params set in method
    """
    def __init__(self, url, project, username=None, password=None):
        self.exp_list = []
        self.exp_json = {}
        self.exp_count = 0
        self.needs_processed = set()
        self.is_processed = set()
        self.missing_set = set()
        self.missing_dict = {}
        self.pipe_name = ""
        self.project = project
        self.url = url
        self.username = username
        self.password = password
        self.report_str = "Pipeline Verification Report for " + self.project + '\n\n'
        self.date_added = {}
        self.after_date = None
        # self.curl_conf

    def verify(self, pipe_name=None, experiments=None, exp_file=None, days_ago=None):
        """
        pipe_name: Name of pipeline to verify: validation, facemask, dcm2nii, or qc.
        experiments: A Python list containing session labels.
        exp_file: Path to a file containing one session label per line.
        days_ago: An integer describing how many days back to verify.

        Pipeline Argument Descriptions:
        validation - Checks for protocol validation at the session level
        facemask - Checks Bias_Recieve, Bias_Transmit, T1w, and T2w scan types for the
                existence of DICOM_DEFACE
        dcm2nii - Checks for existence of NIFTI_RAW if there is DICOM_DEFACED
        qc - Based on series_description, checks for existing xnat:qcAssemssmentData
        """
        self.pipe_name = pipe_name
        # Get experiments into list form
        if not experiments and not exp_file:
            rest_uri = '/REST/experiments?xsiType=xnat:mrSessionData&project='+self.project
            self.exp_json = self.get_rest_data(rest_uri)
            # Build list for all experiments
            for e in self.exp_json:
                self.exp_list.append(e.get('label'))
        elif exp_file: ### To-Do
            pass
        elif experiments: # Already a list
            self.exp_list = experiments
        else:
            print("Couldn't get list of sessions.")
            exit(0)

        # Populate the date_added dictionary for all experiments
        for e in self.exp_json:
            dt = datetime.strptime(e.get('date'), '%Y-%m-%d')
            self.date_added[e.get('label')] = dt

        # Filter only sessions within days_ago
        if days_ago:
            start_date = datetime.today() - timedelta(days_ago)
            self.report_str += "\n**Verifying sessions with a date on or after "+datetime.strftime(start_date, '%Y-%m-%d')+'**'
            new_exp_list = []
            for exp in self.exp_json:
                if (datetime.today() - self.date_added[exp.get('label')]).days < days_ago:
                    new_exp_list.append(exp)
            self.exp_json = new_exp_list
        else:
            self.report_str += "\n**Verifying all sessions**"

        self.exp_count = self.exp_json.__len__()

        if not self.pipe_name:
            self._verify_all_resources()
        elif self.pipe_name == "validation":
            self._verify_validation()
        elif self.pipe_name == "facemask" or self.pipe_name == "dcm2nii":
            self._verify_facemask_dcm2nii()
        elif self.pipe_name == "qc":
            self._verify_qc()
        else:
            print("Invalid pipeline name: " + self.pipe_name)
            print("Choose from the following options: validation, facemask, dcm2nii, or qc")
            sys.exit(0)

    def _verify_validation(self):
        val_uri = '/REST/experiments?xsiType=val:protocolData&project='+self.project
        val_json = self.get_rest_data(val_uri)
        self.needs_processed = set(self.exp_list)

        for item in val_json:
            self.is_processed.add(item.get("session_label"))

        self.missing_set = self.needs_processed - self.is_processed
        self._prepare_report()
        self.is_processed.clear()
        self.needs_processed.clear()
        print("Validation verification complete.")

    def _verify_facemask_dcm2nii(self):
        deface_types = ('Bias_Transmit', 'Bias_Receive', 'T1w', 'T2w')
        missing = {}
        counter = 0
        print("")

        for exp in self.exp_json:
            exp_lbl = exp.get('label')
            counter += 1
            self._update_progress(counter)
            resources = self.get_rest_data(exp.get('URI')+'/scans/*/resources')

            # Skip sessions that are less than a day old
            time_diff = datetime.today() - self.date_added[exp_lbl]
            if time_diff.days < 1:
                continue

            for item in resources:
                scan_id = item.get('cat_id')
                scan_type = item.get('cat_desc')
                resource_lbl = item.get('label')

                if self.pipe_name == "facemask":
                    if scan_type in deface_types:
                        self.needs_processed.add(scan_id)
                    if resource_lbl == "DICOM_DEFACED":
                        self.is_processed.add(scan_id)

                if self.pipe_name == "dcm2nii":
                    if resource_lbl == "DICOM_DEFACED":
                        self.needs_processed.add(scan_id)
                    if resource_lbl == "NIFTI_RAW":
                        self.is_processed.add(scan_id)

            missing[exp_lbl] = []
            for scan in self.needs_processed:
                if scan not in self.is_processed:
                    missing[exp_lbl].append(scan)

            self.is_processed.clear()
            self.needs_processed.clear()

        # Filter out empty sessions, no missing resources
        for key,values in missing.iteritems():
            if values:
                self.missing_dict[key] = values

        self._prepare_report()
        print(self.pipe_name + " verification complete.\n")

    def _verify_qc(self):
        missing = {}
        counter = 0
        print("")

        for exp in self.exp_json:
            counter += 1
            self._update_progress(counter)
            exp_lbl = exp.get('label')
            exp_uri = exp.get('URI')
            scan_results = self.get_rest_data(exp_uri+'/scans')
            qc_results = self.get_rest_data('/REST/experiments?xsiType=xnat:qcAssessmentData&session_label='+exp_lbl)

            # Skip sessions that are less than 2 days old since QC can potentially take awhile
            time_diff = datetime.today() - self.date_added[exp_lbl]
            if time_diff.days < 2:
                continue

            # Find the scans that NEED QC based on scan series_description
            for item in scan_results:
                scan_id = item.get('ID')
                sd = item.get('series_description').lower()

                if (sd.startswith('bold') or sd.startswith('dwi') or sd.startswith('t1w') or sd.startswith('t2w')) \
                    and not (sd.endswith('sbref') or sd.endswith('sbref_old') or sd.endswith('se') \
                    or sd.endswith('se_old') or sd.endswith('meg')):
                    self.needs_processed.add(scan_id)

            # Get the scans that HAVE QC based on qcAssessmentData
            for item in qc_results:
                qc_lbl = item.get('label').split('_')
                # Get scan number from the scan portion of qc resource label
                for sublbl in qc_lbl:
                    if 'SCAN' in sublbl:
                        self.is_processed.add(sublbl[4:])

            missing[exp_lbl] = []
            for scan in self.needs_processed:
                if scan not in self.is_processed:
                    missing[exp_lbl].append(scan)

            self.is_processed.clear()
            self.needs_processed.clear()

        # Filter out empty sessions with no missing QC data
        for key,values in missing.iteritems():
            if values:
                self.missing_dict[key] = values

        self._prepare_report()
        print("QC verification complete.")

    def _verify_all_resources(self):
        """
        DICOM, DICOM_DEFACED, NIFTI, NIFTI_RAW, DEFACE_QC, SNAPSHOTS
            check for anything extra
        LINKED_DATA should have EPRIME, PHYSIO or MOTION subdirectories, nothing else.
        """
        counter = 0

        for exp in self.exp_json:
            counter += 1
            #self._update_progress(counter)
            exp_lbl = exp.get('label')
            exp_id = exp.get('ID')
            exp_uri = exp.get('URI')

            """ REST calls for each scan and resource """
            scan_results = self.get_rest_data(exp_uri+'/scans')

            #https://intradb.humanconnectome.org/REST/experiments/HCPIntradb_E10841/scans/20/resources/135053/files
            print("\n\n  Experiment label: " + exp_lbl)
            for scan in scan_results:
                scan_id = scan.get('ID')
                series_desc = scan.get('series_description')

                resources = self.get_rest_data('/REST/experiments/'+exp_id+'/scans/'+scan_id+'/resources')
                print("\n    Resources for scan " + scan_id + ': ' + series_desc)
                for r in resources:
                    resource_id = r.get('xnat_abstractresource_id')
                    rest_uri = '/REST/experiments/'+exp_id+'/scans/'+scan_id+'/resources/'+resource_id+'/files'
                    files = self.get_rest_data(rest_uri)
                    print(r)
                    print("\n  Files for resource with label "+r.get('label'))
                    for f in files:
                        print(f) 

            ########################################################

            """ Single REST call for full experiment json object - seems to only be resourceCatalog objects
            rest_uri = '/REST/experiments/'+exp_id+'?xsiType=xnat:resourceCatalog&format=json'
            pipeout = sp.Popen(['curl', '-s', '-S', '-u', 'mhileman:hcp@XNAT!',
                                    '-k', '-X', 'GET', self.url+rest_uri], stdout=sp.PIPE)
                        curlout = pipeout.stdout.read()
                        jsonobj = json.loads(curlout)
                        resource_results =  jsonobj.get('items')

            for item in resource_results:
                for child in item.get('children'):
                    for item in child.get('items'):
                        for child in item.get('children'):
                            for item in child.get('items'):
                                print item
                                if item.get('data_fields').get('label') == 'LINKED_DATA':
                                    print item.get('data_fields').get('label')
                                    print "file count: " + str(item.get('data_fields').get('file_count'))
                #exit(0)
            """

    def _prepare_report(self):
        if self.pipe_name:
            self.report_str += '\n'+ self.pipe_name.upper()+" Report:\n"
        if self.pipe_name == "validation":
            self.report_str += '\n'+ str(self.missing_set.__len__()) + " sessions with missing validation data\n"
            for m in self.missing_set:
                self.report_str += '\n'+ m
            self.report_str += '\n'
            self.missing_set.clear()
        else:
            self.report_str += '\n'+ str(self.missing_dict.__len__()) + " sessions with missing " + self.pipe_name + " data\n\n"
            for key,values in self.missing_dict.iteritems():
                self.report_str += key + ' -- '
                for v in values:
                    self.report_str += str(v) + ','
                self.report_str = self.report_str[0:-1]
                self.report_str += '\n'
            self.missing_dict.clear()
        self.report_str += '=============================================\n'

    def report(self, console=True, email=False):
        #sorted(self.missing_dict, key=self.missing_dict.get)
        if console:
            print(self.report_str)
        if email:
            import smtplib
            SMTP_SERVER = 'smtp.gmail.com'
            SMTP_PORT = 587

            recipients = ['hilemanm@mir.wustl.edu']
            sender = 'mhilema@gmail.com'
            subject = 'Pipeline Verification Report: ' + datetime.strftime(datetime.today(), "%Y-%m-%d")

            headers = ["From: " + sender,
                   "Subject: " + subject,
                   "To: hilemanm@mir.wustl.edu"]
            headers = "\r\n".join(headers)
            session = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            session.ehlo()
            session.starttls()
            session.ehlo
            session.login(sender, '8qar9wor')

            session.sendmail(sender, recipients, headers+"\r\n\r\n"+self.report_str)
            session.quit()

    def launch(self, pipe_name, exp):
        """
        Executes a pipeline based on the name argument.
        QC has two fewer params - Need to test empty -parameter
        """
        self.pipe_name = pipe_name
        date_time = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        builddir = '/data/intradb/build/'+exp.get('project')+'/'+date_time
        archivedir = '/data/intradb/archive/'+exp.get('project')+'/arc001'
        os.makedirs(builddir)
        # Get list of scans
        #scans = self.get_scans(exp)
        resource_json = self.get_rest_data('/REST/experiments/'+exp.get('ID')+'/scans/ALL/resources')
        scans = []
        for r in resource_json:
            resource = r.get('label')
            if resource == 'DICOM':
                scans.append(r.get('cat_id'))
        scans.sort(key=int)
        scans = ",".join(scans)

        param = []
        if self.pipe_name == "facemask":
            param.append("FaceMasking/FaceMasking.xml")
            param.append("usebet=1")
            param.append("maskears=1")
            param.append("invasiveness=1.0")
            param.append("existing=Overwrite")
            param.append("runOtherPipelines=Y")
        elif self.pipe_name == "dcm2nii":
            param.append("HCP/HCPDefaceDicomToNifti.xml")
            param.append("notify=0")
            param.append("create_nii=Y")
            param.append("keep_qc=N")
            param.append("overwrite_existing=Y")
            param.append("runOtherPipelines=N")
        elif self.pipe_name == "qc":
            param.append("QC") # To-Do
            param.append("structural_scan_type=T1w,T2w")
            param.append("functional_scan_type=rfMRI,tfMRI")
            param.append("diffusion_scan_type=dMRI")
            param.append("")
            param.append("")

        print(self.pipe_name + " RUNNING on "+ exp.get('label') + \
                      " for subject "+ exp.get('subject_ID'))
        retval = sp.call(['/data/intradb/pipeline/bin/PipelineJobSubmitter',
            '/data/intradb/pipeline/bin/XnatPipelineLauncher',
            '-pipeline', '/data/intradb/pipeline/catalog/' + param[0],
            '-id', exp.get('ID'),
            '-host', self.url, '-u', 'mhileman', '-pwd', 'hcp@XNAT!',
            '-dataType', 'xnat:mrSessionData',
            '-label', exp.get('label'),
            '-supressNotification', '-notify', 'hilemanm@mir.wustl.edu',
            '-project', exp.get('project'),
            '-parameter', 'mailhost=mail.nrg.wustl.edu',
            '-parameter', 'userfullname=M.Hileman',
            '-parameter', 'builddir='+builddir,
            '-parameter', 'adminemail=hilemanm@mir.wustl.edu',
            '-parameter', 'useremail=hilemanm@mir.wustl.edu',
            # Start of paramFile (same for dcm2nii and facemask)
            '-parameter', 'xnat_id='+ exp.get('ID'),
            '-parameter', 'archivedir='+ archivedir, # wasn't here on last run
            '-parameter', 'sessionId='+ exp.get('label'),
            '-parameter', 'project='+exp.get('project'),
            '-parameter', 'scanids='+ scans,
            '-parameter', 'subject='+ exp.get('subject_ID'),
            # Params specific to pipeline type
            '-parameter', param[1],
            '-parameter', param[2],
            '-parameter', param[3],
            '-parameter', param[4],
            '-parameter', param[5]
        ])
        print("\nPipeline process released from queue\n")

    def get_rest_data(self, rest_uri):
        """ (str) --> dict
        Takes a REST URI and returns json data as a dictionary.
        """
        ## To-Do: username:password and curlConf file
        pipeout = sp.Popen(['curl', '-s', '-S', '-u', 'mhileman:hcp@XNAT!',
                            '-k', '-X', 'GET', self.url+rest_uri], stdout=sp.PIPE)
        try:
            curlout = pipeout.stdout.read()
            jsonobj = json.loads(curlout)
        except ValueError:
            print("Could not return json object for given URL")
            print("Attempted Command: curl -s -S -u mhileman:####### -k -X GET " + self.url+rest_uri)
            exit(0)
        #except Exception, e:
        #   print e
        #   exit(0)
        else:
            return jsonobj.get('ResultSet').get('Result')

    def get_scans(exp):
        """ (dict) --> str
        Returns a string representing all scan numbers for an experiment.
        """
        resource_json = get_rest_data('REST/experiments/'+exp.get('ID')+'/scans/ALL/resources')
        scans = []
        for r in resource_json:
            resource = r.get('label')
            if resource == 'DICOM':
                scans.append(r.get('cat_id'))
        scans.sort(key=int)
        sorted = ",".join(scans)
        return sorted


################################################

    def filter_data(self, attr="label", criteria=""):
        """
        Takes all experiment as a json object and returns the specified attribute as a list.
        Criteria is not currently implemented.
        """
        filtered = []
        for item in self.exp_list:
            filtered.append(item.get(attr))
        return filtered

#curlConf='/data/intradb/home/.intradb.curl.conf'

# either going to run on everything, or specific experiement(s)
# could pass in exp list, or file w/ exp,
# otherwise run on everything (warn and require confimation on this)
# if no args (other than pipeline name), run for all and write to log
# else run for those specific exps and write to log
"""
def print_list(list, title):
        for item in list:
            print(item)
        print(title + ": " + str(list.__len__()) + " scans\n")

def wait(seconds):
        sys.stdout.write('Waiting ')
        for i in reversed(range(seconds)):
                time.sleep(1)
                sys.stdout.write(str(i))
        sys.stdout.write(' ')
        print('\n')
"""
#################################################

if __name__ == "__main__":

    """ Instanciation Tests """
    intradb = HcpInterface('https://intradb.humanconnectome.org', 'mhileman', 'hcp@XNAT!', 'HCP_Phase2')
    print("URL: %s \nProject: %s" % (intradb.url, intradb.project))

    """ Get some stuff """
    json = intradb.getJSON('/REST/projects')
    xml = intradb.getXML('/REST/projects/'+intradb.project+'/subjects/100307/experiments/100307_strc/scans/10')
    print("\nJSON object - Projects:")
    print(json)
    print("\nXML object - 100307 subject info:")
    print(xml)

    #pipe = Pipeline('https://intradb.humanconnectome.org', 'HCP_Phase2')
    #pipe.url = 'https://intradb.humanconnectome.org'

    #intradb = ResourceManager('https://intradb.humanconnectome.org', 'mhileman', 'hcp@XNAT!')
    #print("Connected to " + intradb.url + " as " + intradb.username)

    """ Verification Tests """

    """ Processing Tests """
