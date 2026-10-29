import unittest
from types import SimpleNamespace
from gui_dashboard import public_ip, project, visible_sources

class TestMapHelpers(unittest.TestCase):
    def test_public_ip(self):
        self.assertTrue(public_ip('8.8.8.8'))
        self.assertFalse(public_ip('203.0.113.5'))
        self.assertFalse(public_ip('192.168.0.1'))
        self.assertFalse(public_ip('invalid'))

    def test_project(self):
        self.assertEqual(project(0, 0, 0, 0, 360, 170),(180,85))

    def test_demo_mapping(self):
        a=[SimpleNamespace(source_ip='203.0.113.77'), SimpleNamespace(source_ip='203.0.113.77')]
        data=visible_sources(a,demo=True)
        self.assertEqual(len(data),1)
        self.assertEqual(data[0][1],2)
        self.assertFalse(visible_sources(a,demo=False))

    def test_real_never_guesses(self):
        a=[SimpleNamespace(source_ip='192.168.1.5'), SimpleNamespace(source_ip='8.8.8.8')]
        def lookup(ip):return (1,2,'Verified local db')
        self.assertEqual([x[0] for x in visible_sources(a,lookup=lookup)],['8.8.8.8'])

if __name__=='__main__':unittest.main()