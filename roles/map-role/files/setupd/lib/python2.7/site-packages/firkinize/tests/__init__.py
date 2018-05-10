
import json
import mock
import requests
import unittest

from StringIO import StringIO

class BaseTestCase(unittest.TestCase):

    def setUp(self):
        self._patches = []

    def tearDown(self):
        self._unpatchall()

    def _patchfun(self, name):
        patch = mock.patch(name)
        self._patches.append(patch)
        return patch.start()

    def _patchobj(self, cls, member):
        patch = mock.patch.object(cls, member)
        self._patches.append(patch)
        return patch.start()

    def _unpatchall(self):
        for patch in self._patches:
            patch.stop()

    @staticmethod
    def http_response(code, headers=None, body=None):
        resp = requests.Response()
        resp.status_code = code
        if headers:
            resp.headers.update(headers)
        if body:
            resp.raw = StringIO(json.dumps(body))
        return resp
