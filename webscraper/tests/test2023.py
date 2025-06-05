import unittest
import sys
sys.path.append("/Users/cse498/Desktop/Google/cse498-teamgoogle-ss24/webscraper")

import android_bulletin_scraper as android_bulletin_scraper;

'''
"0: patch_level", "1: cve", "2: references", "3: reference_links", "4: type", "5: severity", "6: updated aosp versions", "7: component", "8: subcomponent", "9: android launch version",
"10: kernel launch version", "11: minimum launch version", "12: minimum kernel version", "13: date reported", "14: updated google devices", "15: updated nexus devices",
"16: updated versions", "17: affected versions", "18: not publicly available", "19: bulletin type","20: component code", "21: component code link", "22: date", "23: asb_url"
'''


class Test2023(unittest.TestCase):
    
    '''
    Makes sure that non publicly available references are set to True
    Also tests to make sure component code is set for all of them
    '''
    def test_december(self):
        expected = [
                    ['05', 'CVE-2023-3889','A-295942985','None','None','High','None','Arm components', 'Mali', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01','None'], 
                    
                    ['05', 'CVE-2023-4272','A-296910715','None','None','High','None','Arm components', 'Mali', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-32804','A-272772567','None','None','High','None','Arm components', 'Mali', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21162','A-292004168','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21163','A-292003338','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21164','A-292002918','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21166','A-292002163','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21215','A-291982610','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21216','A-291999952','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21217','A-292087506','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21218','A-292000190','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21228','A-291999439','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21263','A-305095406','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21401','A-305091236','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21402','A-305093885','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21403','A-305096969','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-35690','A-305095935','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-21227','A-291998937','None','None','High','None','Imagination Technologies', 'PowerVR-GPU', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    
                    # Need to look into why the list of M codes is not a list with 2 elements
                    ['05', 'CVE-2023-32818','A-294770901','None','None','High','None','MediaTek components', 'vdec', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08013430, M-ALPS08163896'], 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None'],
                    
                    ['05', 'CVE-2023-32847','A-302982512','None','None','High','None','MediaTek components', 'audio', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08241940'], 'None', '2023-12', 'https://source.android.com/docs/security/bulletin/2023-12-01', 'None']
                    
                    
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2023-12-01", "2023-12")

        file_container.clean_files()
        
        result = file_container.get_files()[0][32:53]
        for expected_row, result_row in zip(result, expected):
            self.assertEqual(expected_row, result_row)
            
    '''
    Tests for the when the Android Launch Version, Kernel Launch Version, and Minimum Launch Version is not None and the cve is none
    '''
    def test_november(self):
        expected = [
                    ['05', 'None','A-273609724','None','None','None','None','Kernel LTS', 'None', '11', '5.4', '5.4.233', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-11', 'https://source.android.com/docs/security/bulletin/2023-11-01', 'None'],
                    
                    ['05', 'None','A-273609966','None','None','None','None','Kernel LTS', 'None', '12', '5.4', '5.4.233', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-11', 'https://source.android.com/docs/security/bulletin/2023-11-01', 'None'],
                    
                    ['05', 'None','A-273610287','None','None','None','None','Kernel LTS', 'None', '12', '5.10', '5.10.168', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-11', 'https://source.android.com/docs/security/bulletin/2023-11-01', 'None'],
                    
                    ['05', 'None','A-273610950','None','None','None','None','Kernel LTS', 'None', '13', '5.10', '5.10.168', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-11', 'https://source.android.com/docs/security/bulletin/2023-11-01', 'None'],
                    
                    ['05', 'None','A-273610973','None','None','None','None','Kernel LTS', 'None', '13', '5.15', '5.15.94', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-11', 'https://source.android.com/docs/security/bulletin/2023-11-01', 'None'],
                    
                    
                    
                    
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2023-11-01", "2023-11")

        file_container.clean_files()
        
        result = file_container.get_files()[0]
        for expected_row in expected:
            self.assertTrue(expected_row not in result)
            
    '''
    Tests for the when the patch level is 06
    '''
    def test_october(self):
        expected = [
                    ['06', 'CVE-2023-4863','A-299477569','None','RCE','Critical','11, 12, 12L, 13','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-10', 'https://source.android.com/docs/security/bulletin/2023-10-01', 'Note: There are indications that the following may be under limited,  '
+  'targeted exploitation.  CVE-2023-4863CVE-2023-4211']
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2023-10-01", "2023-10")

        file_container.clean_files()
        
        result = file_container.get_files()[0][-1]
        self.assertEqual(expected[0], result)
        
        
    '''
    Tests for when a row has mutliple cves on the website
    '''
    def test_september(self):
        expected = [
                    ['01', 'CVE-2023-35670','None','None','None','None','None','Google Play system updates', 'MediaProvider', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-09', 'https://source.android.com/docs/security/bulletin/2023-09-01', 'None'],
                    
                    ['01', 'CVE-2023-35683','None','None','None','None','None','Google Play system updates', 'MediaProvider', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-09', 'https://source.android.com/docs/security/bulletin/2023-09-01', 'None']
                    
                    
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2023-09-01", "2023-09")

        file_container.clean_files()
        
        result = file_container.get_files()[0]
        first_cve = result[21]
        second_cve = result[-1]
        self.assertEqual(expected[0], first_cve)
        self.assertEqual(expected[1], second_cve)
        
    '''
    Tests for when a row has mutliple cves on the website and Upstream Kernel as component code
    '''
    def test_september(self):
        expected = [
                    ['01', 'CVE-2023-21282','None','None','None','None','None','Google Play system updates', 'Media Codecs', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['01', 'CVE-2023-21132','None','None','None','None','None','Google Play system updates', 'Permission Controller', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['01', 'CVE-2023-21133','None','None','None','None','None','Google Play system updates', 'Permission Controller', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['01', 'CVE-2023-21134','None','None','None','None','None','Google Play system updates', 'Permission Controller', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['01', 'CVE-2023-21140','None','None','None','None','None','Google Play system updates', 'Permission Controller', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['01', 'CVE-2023-20965','None','None','None','None','None','Google Play system updates', 'WiFi', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['01', 'CVE-2023-21242','None','None','None','None','None','Google Play system updates', 'WiFi', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['05', 'CVE-2023-21264','A-279739439','None','EoP','Critical','None','Kernel', 'KVM', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['Upstream kernel', '[2]'], {'Upstream kernel' : 'https://android.googlesource.com/kernel/common/+/b35a06182451f', '2' : 'https://android.googlesource.com/kernel/common/+/53625a846a7b4'}, '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None'],
                    
                    ['05', 'CVE-2020-29374','A-174737879','None','EoP','High','None','Kernel', 'COW', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['Upstream kernel', '[2]','[3]', '[4]', '[5]', '[6]'], {'Upstream kernel' : 'https://android.googlesource.com/kernel/common/+/a308c71bf1e6e', '2' : 'https://android.googlesource.com/kernel/common/+/52d1e606ee733', '3':
                        'https://android.googlesource.com/kernel/common/+/1a0cf26323c8', '4' : 'https://android.googlesource.com/kernel/common/+/09854ba94c6a', '5' : 'https://android.googlesource.com/kernel/common/+/be068f2903', '6' : 'https://android.googlesource.com/kernel/common/+/17839856fd588'}, '2023-08', 'https://source.android.com/docs/security/bulletin/2023-08-01', 'None']
                    
                    
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2023-08-01", "2023-08")

        file_container.clean_files()
        
        result = file_container.get_files()[0]
        first_cve = result[31]
        second_cve = result[32]
        third_cve = result[-4]
        fourth_cve = result[-3]
        fifth_cve = result[-2]
        sixth_cve = result[33]
        seventh_cve = result[-1]
        eigth_cve = result[34]
        ninth_cve = result[35]
        
        self.assertEqual(expected[0], first_cve)
        self.assertEqual(expected[1], second_cve)
        self.assertEqual(expected[2], third_cve)
        self.assertEqual(expected[3], fourth_cve)
        self.assertEqual(expected[4], fifth_cve)
        self.assertEqual(expected[5], sixth_cve)
        self.assertEqual(expected[6], seventh_cve)
        self.assertEqual(expected[7], eigth_cve)
        self.assertEqual(expected[8], ninth_cve)
            
            
            
if __name__ == '__main__':
    unittest.main()