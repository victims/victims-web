import unittest

from victims_web import application


class FlaskTestCase(unittest.TestCase):

    def setUp(self):
        application.app.config['TESTING'] = True
        self.app = application.app.test_client()
