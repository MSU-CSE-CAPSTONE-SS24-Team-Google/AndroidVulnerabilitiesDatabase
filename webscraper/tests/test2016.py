import unittest
import sys
sys.path.append("/Users/cse498/Desktop/Google/cse498-teamgoogle-ss24/webscraper")

import android_bulletin_scraper as android_bulletin_scraper;

'''
"0: patch_level", "1: cve", "2: references", "3: reference_links", "4: type", "5: severity", "6: updated aosp versions", "7: component", "8: subcomponent", "9: android launch version",
"10: kernel launch version", "11: minimum launch version", "12: minimum kernel version", "13: date reported", "14: updated google devices", "15: updated nexus devices",
"16: updated versions", "17: affected versions", "18: not publicly available", "19: bulletin type","20: component code", "21: component code link", "22: date", "23: asb_url"
'''


class Test2016(unittest.TestCase):
    
    
    unittest.TestCase.maxDiff = None
    '''
    Tests for the columns Date reported, and updated google devices for patch level 01 and 05
    '''
    def test_december(self):
        
        # Need to look at why in is being attacted to CURL
        expected = [
                    ['01', 'CVE-2016-5419','A-31271247','None','None','High','7.0','Remote code execution vulnerability inCURL/LIBCURL', 'None', 'None', 'None', 'None', 'None', 'Aug 3, 2016', 'All', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2016-12', 'https://source.android.com/docs/security/bulletin/2016-12-01', 'None'],
                    
                    ['01', 'CVE-2016-5420','A-31271247','None','None','High','7.0','Remote code execution vulnerability inCURL/LIBCURL', 'None', 'None', 'None', 'None', 'None', 'Aug 3, 2016', 'All', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2016-12', 'https://source.android.com/docs/security/bulletin/2016-12-01', 'None'],
                    
                    ['01', 'CVE-2016-5421','A-31271247','None','None','High','7.0','Remote code execution vulnerability inCURL/LIBCURL', 'None', 'None', 'None', 'None', 'None', 'Aug 3, 2016', 'All', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2016-12', 'https://source.android.com/docs/security/bulletin/2016-12-01', 'None'],
                    
                    ['05', 'CVE-2016-4794','A-31596597','None','None','Critical','None','Elevation of privilege vulnerability inkernel memory subsystem', 'None', 'None', 'None', 'None', 'None', 'Apr 17, 2016', 'Pixel C, Pixel, Pixel XL', 'None', 'None', 'None', 'False', 'Android OS', ['Upstream kernel', '[2]'], {'Upstream kernel' : 'http://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/commit/?id=6710e594f71ccaad8101bc64321152af7cd9ea28', '2' : 'http://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/commit/?id=4f996e234dad488e5d9ba0858bc1bae12eff82c3'}, '2016-12', 'https://source.android.com/docs/security/bulletin/2016-12-01', 'None'],
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2016-12-01", "2016-12")

        file_container.clean_files()
        
        result = file_container.get_files()[0]
        
        first_cve = result[0]
        second_cve = result[1]
        third_cve = result[2]
        fourth_cve = result[16]
        
        self.assertEqual(expected[0], first_cve)
        self.assertEqual(expected[1], second_cve)
        self.assertEqual(expected[2], third_cve)
        self.assertEqual(expected[3], fourth_cve)
        
    '''
    Tests for the column Updated Nexus devices
    '''
    def test_august(self):
        
        # Need to look at why in is being attacted to CURL
        expected = [
                    ['01', 'CVE-2016-3819','A-28533562',{'A-28533562' : 'https://android.googlesource.com/platform/frameworks/av/+/590d1729883f700ab905cdc9ad850f3ddd7e1f56'},'None','Critical', '4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1','Remote code execution vulnerability in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'May 2, 2016', 'None', 'All Nexus', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2016-08', 'https://source.android.com/docs/security/bulletin/2016-08-01', 'None'],
                    
                    ['01', 'CVE-2016-3820','A-28673410',{'A-28673410' : 'https://android.googlesource.com/platform/external/libavc/+/a78887bcffbc2995cf9ed72e0697acf560875e9e'},'None','Critical', '6.0, 6.0.1','Remote code execution vulnerability in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'May 6, 2016', 'None', 'All Nexus', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2016-08', 'https://source.android.com/docs/security/bulletin/2016-08-01', 'None'],
                    
                    ['01', 'CVE-2016-3821','A-28166152',{'A-28166152' : 'https://android.googlesource.com/platform/frameworks/av/+/42a25c46b844518ff0d0b920c20c519e1417be69'},'None','Critical', '4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1','Remote code execution vulnerability in Mediaserver', 'None', 'None', 'None', 'None', 'None', 'Google internal', 'None', 'All Nexus', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2016-08', 'https://source.android.com/docs/security/bulletin/2016-08-01', 'None'],
                    
                    
                    
                  
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2016-08-01", "2016-08")

        file_container.clean_files()
        
        result = file_container.get_files()[0][:3]
        
        for expected_row, result_row in zip(expected, result):
            self.assertEqual(expected_row, result_row) 
            
            
if __name__ == '__main__':
    unittest.main()