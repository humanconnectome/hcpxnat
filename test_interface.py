from interface import HcpInterface
import unittest


class TestHcpInterface(unittest.TestCase):

    def setUp(self):
        self.idb = HcpInterface('https://intradb.humanconnectome.org', 'mhileman', 'hcp@XNAT!', 'HCP_Phase2')
        self.cdb = HcpInterface('https://db.humanconnectome.org', 'admin', 'hcpAdmiN181')
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

    @unittest.expectedFailure
    def test_getSubjectSessions(self):
        session_labels = self.idb.getSubjectSessions()

        self.assertTrue('100307_strc' in session_labels)

    @unittest.skip("test not implemented")
    def test_getProjectSessions(self):
        pass

    ## Xml Tests
    def test_getXml(self):
        uri = '/REST/projects/'+self.idb.project+'/subjects/100307/experiments/100307_strc/scans/10'
        xml = self.idb.getXml(uri)

        self.assertTrue('100307_strc' in xml)

    def test_getScanXmlElement(self):
        dbScanID = self.idb.getScanXmlElement('xnat:dbID')

        self.assertTrue(dbScanID == '103')

    ## General Tests
    def test_getHeaderField(self):
        uri = 'https://db.humanconnectome.org/data/subjects/ConnectomeDB_S00381?format=json'
        server = self.getHeaderField(uri, 'Server')

        self.assertTrue(server == 'Apache')



## Excecute Tests
suite = unittest.TestLoader().loadTestsFromTestCase(TestHcpInterface)
unittest.TextTestRunner(verbosity=2).run(suite)
