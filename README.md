## hcpxnat
###### Python-XNAT interface for HCP
Clone hcpxnat into the root of your project and instantiate like so:

    from hcpxnat.interface import HcpInterface
    intradb = HcpInterface(url='https://intradb.humanconnectome.org',
                           username='admin', password='pass',
                           project='HCP_Phase2')
    # Or with a config file
    intradb = HcpInterface(config='/home/user/.hcpxnat.cfg')

##### Config File Example:
    [auth]
    username=admin
    password=pass

    [site]
    hostname=https://hcpx-demo.humanconnectome.org
    project=HCP_Q3

##### Usage Examples:
    >>> sessions = intradb.getSessions()
    >>> sessions[0].get('ID')
    u'HCP_E00001'

    >>> intradb.subject_label = '100'
    >>> intradb.session_label = '100_strc'
    >>> intradb.getSessionId()
    u'HCP_E01010'

    >>> intradb.getSessionScans()
    --> Returns list of all scans as dict

    >>> intradb.scan_id = '10'
    >>> resources = intradb.getScanResources()
    >>> resources[0]['label']
    u'DICOM'

    >>> intradb.getSubjects(project='HCP')
    [{u'ID': u'HCP_S123', u'URI': u'/data/HCP_S123', u'insert_date': u'2014-06-19 23:02:01.383',  
      u'insert_user': u'admin', u'label': u'3214', u'project': u'HCP'}, ...]

    >>> intradb.getUsers()
    [{u'email': u'bob@u.edu', u'firstname': u'Bob', u'lastname': u'Sagot', u'login': u'bsag',  
      u'xdat_user_id': u'56'}, ...]

    >>> intradb.setExperimentElement('xsiType', 'BMI', 120)
    
