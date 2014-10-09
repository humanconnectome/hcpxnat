#!/usr/bin/env python
from interface import HcpInterface
import unittest
import os


class TestHcpInterface(unittest.TestCase):

    def setUp(self):
        idb_config_file = os.path.join(os.path.expanduser('~'),
            '.hcpxnat_intradb.cfg')
        cdb_config_file = os.path.join(os.path.expanduser('~'),
            '.hcpxnat_cdb.cfg')
        self.idb = HcpInterface(config=idb_config_file)
        self.cdb = HcpInterface(config=cdb_config_file)
        self.idb.subject_label = '100307'
        self.idb.session_label = '100307_strc'
        self.idb.scan_id = '19'

    def tearDown(self):
        pass

    ## Json Tests
    def test_getJson(self):
        json_obj = self.idb.getJson('/REST/projects')
        project_list = [item.get('ID') for item in json_obj]

        self.assertTrue(self.idb.project in project_list)

    @unittest.expectedFailure
    def test_getSubjectJson(self):
        # sub_json = self.cdb.getSubjectJson('100408')
        self.assertTrue(False)

    @unittest.expectedFailure
    def test_getSessionJson(self):
        self.assertTrue(False)

    def test_getSessions_project(self):
        sessions = self.idb.getSessions('HCP_Phase2')
        session_labels = [s.get('label') for s in sessions]

        self.assertTrue(len(session_labels) > 100)

    def test_getSessions_all(self):
        sessions = self.idb.getSessions()
        session_labels = [s.get('label') for s in sessions]

        self.assertTrue(len(session_labels) > 100)

    def test_getSubjectSessions(self):
        sessions = self.idb.getSubjectSessions()
        session_labels = [s.get('label') for s in sessions]

        self.assertTrue('100307_strc' in session_labels)

    ## Xml Tests
    def test_getXml(self):
        uri = '/REST/projects/'+self.idb.project+ \
            '/subjects/100307/experiments/100307_strc/scans/10'
        xml = self.idb.getXml(uri)
        self.assertTrue('100307_strc' in xml)

    def test_getScanXmlElement(self):
        dbScanID = self.idb.getScanXmlElement('xnat:dbID')
        self.assertTrue(dbScanID == '103')

    @unittest.expectedFailure
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
        """
        Testing two sessions since json object returned isn't always the same
        """
        # 100307_strc session label
        # sessionIdA = self.idb.getSessionId()
        # print sessionIdA

        # self.idb.session_label = '705341_strc'
        # sessionIdB = self.idb.getSessionId()
        # print sessionIdB

        self.idb.project = 'NKI'
        self.idb.session_label = '0142673'
        sessionIdC = self.idb.getSessionId()
        # print sessionIdC

        self.assertTrue(sessionIdC == 'HCPIntradb_E36546')
        # self.assertTrue(sessionIdA == 'HCPIntradb_E04465'
        #             and sessionIdB == 'HCPIntradb_E15574'
        #             and sessionIdC == 'HCPIntradb_E36546')

    def test_getSubjectId(self):
        subID = self.idb.getSubjectId()
        self.assertTrue(subID == 'HCPIntradb_S01642')

    def test_getSessionScans(self):
        scans = self.idb.getSessionScans()
        self.assertTrue(scans[0].get('ID') == '1')

    def test_getSessionScanIds(self):
        ids = self.idb.getSessionScanIds()
        self.assertTrue(ids.__len__() > 5)

    def test_getSessionSubject(self):
        sub = self.idb.getSessionSubject()
        self.assertTrue(sub == '100307')

    def test_experimentExists(self):
        self.assertTrue(self.idb.experimentExists() and not
                        self.idb.experimentExists('asdf'))

    def test_getExperiments(self):
        experiments = self.idb.getExperiments(project='HCP_Phase2',
                                              xsi='xnat:mrSessiondata')
        self.assertTrue(len(experiments) > 10)


if __name__ == '__main__':

    alltests = unittest.TestLoader().loadTestsFromTestCase(TestHcpInterface)
    # fast = unittest.TestSuite()
    # fast.addTest(TestHcpInterface.test_getSessionId)
    suite = alltests
    unittest.TextTestRunner(verbosity=2).run(suite)
