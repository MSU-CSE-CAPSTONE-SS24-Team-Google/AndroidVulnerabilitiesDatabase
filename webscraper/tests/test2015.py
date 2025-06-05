import unittest
import sys
sys.path.append("/Users/cse498/Desktop/Google/cse498-teamgoogle-ss24/webscraper")

import android_bulletin_scraper as android_bulletin_scraper;

'''
"0: patch_level", "1: cve", "2: references", "3: reference_links", "4: type", "5: severity", "6: updated aosp versions", "7: component", "8: subcomponent", "9: android launch version",
"10: kernel launch version", "11: minimum launch version", "12: minimum kernel version", "13: date reported", "14: updated google devices", "15: updated nexus devices",
"16: updated versions", "17: affected versions", "18: not publicly available", "19: bulletin type","20: component code", "21: component code link", "22: date", "23: asb_url"
'''


class Test2015(unittest.TestCase):
    
    
    unittest.TestCase.maxDiff = None
    '''
    Tests for the column updated versions and when a cve is related to multiple references
    '''
    def test_december(self):
        expected = [
                    ['01', 'CVE-2015-6616','ANDROID-24630158',{'ANDROID-24630158' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/257b3bc581bbc65318a4cc2d3c22a07a4429dc1d'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', '6.0 and below', 'None', 'False', 'Android OS', 'None', 'None', '2015-12', 'https://source.android.com/docs/security/bulletin/2015-12-01', 'None'],
                    
                    ['01', 'CVE-2015-6616','ANDROID-23882800',{'ANDROID-23882800' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/0d35dd2068d6422c3c77fb68f248cbabf3d0b10c'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', '6.0 and below', 'None', 'False', 'Android OS', 'None', 'None', '2015-12', 'https://source.android.com/docs/security/bulletin/2015-12-01', 'None'],
                    
                    ['01', 'CVE-2015-6616','ANDROID-17769851',{'ANDROID-17769851' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/dedaca6f04ac9f95fabe3b64d44cd1a2050f079e'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', '5.1 and below', 'None', 'False', 'Android OS', 'None', 'None', '2015-12', 'https://source.android.com/docs/security/bulletin/2015-12-01', 'None'],
                    
                    ['01', 'CVE-2015-6616','ANDROID-24441553',{'ANDROID-24441553' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/5d101298d8b0a78a1dc5bd26dbdada411f4ecd4d'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Sep 22, 2015', 'None', 'None', '6.0 and below', 'None', 'False', 'Android OS', 'None', 'None', '2015-12', 'https://source.android.com/docs/security/bulletin/2015-12-01', 'None'],
                    
                    ['01', 'CVE-2015-6616','ANDROID-24157524',{'ANDROID-24157524' : 'https://android.googlesource.com/platform%2Fexternal%2Flibavc/+/2ee0c1bced131ffb06d1b430b08a202cd3a52005'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Sep 08, 2015', 'None', 'None', '6.0', 'None', 'False', 'Android OS', 'None', 'None', '2015-12', 'https://source.android.com/docs/security/bulletin/2015-12-01', 'None'],
                    
                    ['01', 'CVE-2015-6617','ANDROID-23648740',{'ANDROID-23648740' : 'https://android.googlesource.com/platform%2Fexternal%2Fskia/+/a1d8ac0ac0af44d74fc082838936ec265216ab60'},'None','Critical','None','Remote Code Execution Vulnerability in Skia', 'None', 'None', 'None', 'None', 'None', 'Google internal', 'None', 'None', '6.0 and below', 'None', 'False', 'Android OS', 'None', 'None', '2015-12', 'https://source.android.com/docs/security/bulletin/2015-12-01', 'None'],
                    
                   
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2015-12-01", "2015-12")

        file_container.clean_files()
        
        result = file_container.get_files()[0][:6]
        
        for expected_row, result_row in zip(expected, result):
            self.assertEqual(expected_row, result_row)  
            
            
    def test_november(self):
        expected = [
                    ['01', 'CVE-2015-6608','ANDROID-19779574',{'ANDROID-19779574' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/8ec845c8fe0f03bc57c901bc484541bdd6a7cf80'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', 'None', '5.0, 5.1, 6.0', 'False', 'Android OS', 'None', 'None', '2015-11', 'https://source.android.com/docs/security/bulletin/2015-11-01', 'None'],
                    
                    ['01', 'CVE-2015-6608','ANDROID-23680780',{'ANDROID-23680780' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/c6a2815eadfce62702d58b3fa3887f24c49e1864'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', 'None', '5.0, 5.1, 6.0', 'False', 'Android OS', 'None', 'None', '2015-11', 'https://source.android.com/docs/security/bulletin/2015-11-01', 'None'],
                    
                    ['01', 'CVE-2015-6608','ANDROID-23876444',{'ANDROID-23876444' : 'https://android.googlesource.com/platform%2Fexternal%2Faac/+/b3c5a4bb8442ab3158fa1f52b790fadc64546f46'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', 'None', '5.0, 5.1, 6.0', 'False', 'Android OS', 'None', 'None', '2015-11', 'https://source.android.com/docs/security/bulletin/2015-11-01', 'None'],
                    
                    ['01', 'CVE-2015-6608','ANDROID-23881715',{'ANDROID-23881715' : 'https://android.googlesource.com/platform%2Fexternal%2Ftremolo/+/3830d0b585ada64ee75dea6da267505b19c622fd'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', 'None', '4.4, 5.0, 5.1, 6.0', 'False', 'Android OS', 'None', 'None', '2015-11', 'https://source.android.com/docs/security/bulletin/2015-11-01', 'None'],
                    
                    ['01', 'CVE-2015-6608','ANDROID-14388161',{'ANDROID-14388161' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/3878b990f7d53eae7c2cf9246b6ef2db5a049872'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', 'None', '4.4 and 5.1', 'False', 'Android OS', 'None', 'None', '2015-11', 'https://source.android.com/docs/security/bulletin/2015-11-01', 'None'],
                    
                    ['01', 'CVE-2015-6608','ANDROID-23658148',{'ANDROID-23658148' : 'https://android.googlesource.com/platform%2Fframeworks%2Fav/+/f3eb82683a80341f5ac23057aab733a57963cab2'},'None','Critical','None','Remote Code Execution Vulnerabilities in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google Internal', 'None', 'None', 'None', '5.0, 5.1, 6.0', 'False', 'Android OS', 'None', 'None', '2015-11', 'https://source.android.com/docs/security/bulletin/2015-11-01', 'None'],
                    
                    
                   
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2015-11-01", "2015-11")

        file_container.clean_files()
        
        result = file_container.get_files()[0][:6]
        
        for expected_row, result_row in zip(expected, result):
            self.assertEqual(expected_row, result_row)            
            
            
if __name__ == '__main__':
    unittest.main()