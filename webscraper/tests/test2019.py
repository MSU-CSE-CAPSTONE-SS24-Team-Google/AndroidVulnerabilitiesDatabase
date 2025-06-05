import unittest
import sys
sys.path.append("/Users/cse498/Desktop/Google/cse498-teamgoogle-ss24/webscraper")

import android_bulletin_scraper as android_bulletin_scraper;

'''
"0: patch_level", "1: cve", "2: references", "3: reference_links", "4: type", "5: severity", "6: updated aosp versions", "7: component", "8: subcomponent", "9: android launch version",
"10: kernel launch version", "11: minimum launch version", "12: minimum kernel version", "13: date reported", "14: updated google devices", "15: updated nexus devices",
"16: updated versions", "17: affected versions", "18: not publicly available", "19: bulletin type","20: component code", "21: component code link", "22: date", "23: asb_url"
'''


class Test2019(unittest.TestCase):
    
    
    unittest.TestCase.maxDiff = None
    '''
    Tests for when a row does not have a cve or reference
    '''
    def test_october(self):
        
        # Need to look at why in is being attacted to CURL
        expected = [
                    ['01', 'CVE-2019-2184','A-134578122',{'A-134578122' : 'https://android.googlesource.com/platform/frameworks/av/+/7802c68aebf7908983508fd4a52a7d53746a80eb'},'RCE','Critical','7.1.1, 7.1.2, 8.0, 8.1, 9','Media framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2019-10', 'https://source.android.com/docs/security/bulletin/2019-10-01', 'None'],
                    
                    ['01', 'CVE-2019-2185','A-136173699',{'A-136173699' : 'https://android.googlesource.com/platform/frameworks/av/+/5af096cb013b392ee594dc61140a61513fca97da'},'RCE','Moderate','10','Media framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2019-10', 'https://source.android.com/docs/security/bulletin/2019-10-01', 'None'],
                                        
                    ['01', 'CVE-2019-2186','A-136175447',{'A-136175447' : 'https://android.googlesource.com/platform/frameworks/av/+/5af096cb013b392ee594dc61140a61513fca97da'},'RCE','Moderate','10','Media framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2019-10', 'https://source.android.com/docs/security/bulletin/2019-10-01', 'None'],
                                        
                    ['01', 'CVE-2019-2110','A-69703445',{'A-69703445' : 'https://android.googlesource.com/platform/frameworks/base/+/da7203b66876a680fad56a5aafe3d84ae8354d4f'},'ID','High','9','Media framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2': 'https://android.googlesource.com/platform/frameworks/native/+/0283c73ccf4c54d0ed8e8b479ea76cb1e1f815d8'}, '2019-10', 'https://source.android.com/docs/security/bulletin/2019-10-01', 'None'],
                    
                   
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2019-10-01", "2019-10")

        file_container.clean_files()
        
        result = file_container.get_files()[0][1:5]
        
        for expected_row, result_row in zip(expected, result):
            self.assertEqual(expected_row, result_row) 
        
    
            
if __name__ == '__main__':
    unittest.main()