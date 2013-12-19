#!/usr/bin/env python
from interface import HcpInterface
import unittest


class TestHcpInterface(unittest.TestCase):

    def setUp(self):
        idb_config_file = '/home/NRG/mhilem01/.hcpxnat_intradb.cfg'
        cdb_config_file = '/home/NRG/mhilem01/.hcpxnat_cdb.cfg'
        self.idb = HcpInterface('https://intradb.humanconnectome.org',
            project='HCP_Phase2', config=idb_config_file)
        self.cdb = HcpInterface('https://db.humanconnectome.org',
            project='HCP_Q3', config=cdb_config_file)
        self.idb.subject_label = '100307'
        self.idb.session_label = '100307_strc'
        self.idb.scan_id = '19'

    ## Json Tests
    def test_getJson(self):
        json_obj = self.idb.getJson('/REST/projects')
        project_list = list()

        for item in json_obj:
            project_list.append(item.get('ID'))

        self.assertTrue(self.idb.project in project_list)

    @unittest.expectedFailure
    def test_getSubjectJson(self):
        sub_json = self.cdb.getSubjectJson('100408')
        self.assertTrue(False)

    @unittest.expectedFailure
    def test_getSessionJson(self):
        self.assertTrue(False)

    def test_getProjectSessions(self):
        sessions = self.idb.getProjectSessions()
        session_labels = list()

        for s in sessions:
            session_labels.append(s.get('label'))

        self.assertTrue(session_labels.__len__() > 100)

    def test_getSubjectSessions(self):
        sessions = self.idb.getSubjectSessions()
        session_labels = list()

        for s in sessions:
            session_labels.append(s.get('label'))

        self.assertTrue('100307_strc' in session_labels)

    ## Xml Tests
    def test_getXml(self):
        uri = '/REST/projects/'+self.idb.project+'/subjects/100307/experiments/100307_strc/scans/10'
        xml = self.idb.getXml(uri)

        self.assertTrue('100307_strc' in xml)

    def test_getScanXmlElement(self):
        dbScanID = self.idb.getScanXmlElement('xnat:dbID')

        self.assertTrue(dbScanID == '103')

    def test_getSubjectXmlElement(self):
        date = self.idb.getSubjectXmlElement('xnat:age')

        self.assertTrue(date == '26')

    def test_getSessionXmlElement(self):
        date = self.idb.getSessionXmlElement('xnat:date')

        self.assertTrue(date == '2012-08-23')

    ## General Tests
    def test_getHeaderField(self):
        uri = "/REST/projects"
        server = self.cdb.getHeaderField(uri, 'Server')

        self.assertTrue(server == 'Apache')

    ## Convenience Method Tests

    def test_getSessionId(self):
        sessionID = self.idb.getSessionId()

        self.assertTrue(sessionID == 'HCPIntradb_E04465')

    def test_getSubjectId(self):
        subID = self.idb.getSubjectId()

        self.assertTrue(subID == 'HCPIntradb_S01642')

    def test_getSessionScans(self):
        scans = self.idb.getSessionScans()

        self.assertTrue(scans[0].get('ID') == '1')

    def test_getSessionScanIds(self):
        ids = self.idb.getSessionScanIds()

        self.assertTrue(ids.__len__() > 5)


## Excecute Tests
suite = unittest.TestLoader().loadTestsFromTestCase(TestHcpInterface)
unittest.TextTestRunner(verbosity=2).run(suite)
