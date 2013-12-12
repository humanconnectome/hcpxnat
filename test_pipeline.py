#!/usr/bin/env python
from pipeline import PipelineManager
import unittest

# python launchIntradbPipeline.py -u user -p pass -H intradb... -s 100307_strc -P facemask

class TestPipelineManager(unittest.TtestCase):

    def setUp(self):
        pipe = PipelineManager()

    def test_launch(self):
