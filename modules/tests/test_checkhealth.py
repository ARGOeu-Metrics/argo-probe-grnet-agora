import unittest
import responses
from agora_probes.checkhealth import AgoraHealthCheck

class AgoraHealthCheckTests(unittest.TestCase):
    URL = 'https://localhost.com'

    def setUp(self):
        args = ['-U', self.URL]
        self.probe = AgoraHealthCheck(args)

    def testCreation(self):
        self.assertEqual(self.probe.args.url, self.URL)

if __name__ == '__main__':
    unittest.main()