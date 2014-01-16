hcpxnat
=======

Python-XNAT interface for HCP

After cloning into the root of your project, include as follows:
from hcpxnat.interface import HcpInterface


Instantiation:
intradb = HcpInterface(url='https://intradb.humanconnectome.org', project='HCP_Phase2',
                       username='admin', password='pass')

Instantiation with Config File:
intradb = HcpInterface(config='/home/NRG/user/.hcpxnat.cfg')

Config File Example:
[auth]
username=admin
password=pass

[site]
hostname=https://hcpx-demo.humanconnectome.org
project=HCP_Q3


Usage Examples:
intradb.subject_label = '100307'
intradb.session_label = '100307_strc'
...
