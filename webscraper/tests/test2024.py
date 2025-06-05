import unittest
import sys
sys.path.append("/Users/cse498/Desktop/Google/cse498-teamgoogle-ss24/webscraper")

import android_bulletin_scraper as android_bulletin_scraper;

'''
"0: patch_level", "1: cve", "2: references", "3: reference_links", "4: type", "5: severity", "6: updated aosp versions", "7: component", "8: subcomponent", "9: android launch version",
"10: kernel launch version", "11: minimum launch version", "12: minimum kernel version", "13: date reported", "14: updated google devices", "15: updated nexus devices",
"16: updated versions", "17: affected versions", "18: not publicly available", "19: bulletin type","20: component code", "21: component code link", "22: date", "23: asb_url"
'''


class Test2024(unittest.TestCase):
    
    '''
    Regular format for a bulletin page
    '''
    def test_february(self):
        expected = [
                    ['01', 'CVE-2024-0029','A-305664128',{'A-305664128': 'https://android.googlesource.com/platform/frameworks/base/+/9b10fd9718f4e6f6843adbfc14e46a93aab93aad'},'EoP','High','13','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0032','A-283962634',{'A-283962634': 'https://android.googlesource.com/platform/packages/providers/DownloadProvider/+/5acd646e0cf63e2c9c0862da7e03531ef0074394'},'EoP','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2' : 'https://android.googlesource.com/platform/frameworks/base/+/4af5db76f25348849252e0b8a08f4a517ef842b7'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01','None'],
                    
                    ['01', 'CVE-2024-0034','A-298094386',{'A-298094386': 'https://android.googlesource.com/platform/frameworks/base/+/653f7b0d234693309dc86161af01831b64033fe6'},'EoP','High','11, 12, 12L, 13','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01','None'],
                    
                    ['01', 'CVE-2024-0036','A-230492947',{'A-230492947': 'https://android.googlesource.com/platform/frameworks/base/+/3eaaa9687e90c65f51762deb343f18bef95d4e8e'},'EoP','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0038','A-309426390',{'A-309426390': 'https://android.googlesource.com/platform/frameworks/base/+/3e88d987235f5a2acd50a9b6bad78dbbf39cb079'},'EoP','High','14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0041','A-300741186',{'A-300741186': 'https://android.googlesource.com/platform/frameworks/base/+/d6f7188773409c8f5ad5fc7d3eea5b1751439e26'},'EoP','High','14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2023-40122','A-286235483',{'A-286235483': 'https://android.googlesource.com/platform/frameworks/base/+/55fc00a0788ea0995fe0851616b9ac21710a2931'},'ID','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0037','A-292104015',{'A-292104015': 'https://android.googlesource.com/platform/frameworks/base/+/55fc00a0788ea0995fe0851616b9ac21710a2931'},'ID','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0040','A-300007708',{'A-300007708': 'https://android.googlesource.com/platform/frameworks/av/+/2ca6c27dc0336fd98f47cfb96dc514efa98e8864'},'ID','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0031','A-297524203',{'A-297524203': 'https://android.googlesource.com/platform/packages/modules/Bluetooth/+/de53890aaca2ae08b3ee2d6e3fd25f702fdfa661'},'RCE','Critical','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01','None'],
                    
                    ['01', 'CVE-2024-0014','A-304082474','None','EoP','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01','None'],
                    
                    ['01', 'CVE-2024-0033','A-294609150',{'A-294609150': 'https://android.googlesource.com/platform/frameworks/native/+/aa98edf0ce9dde4886979658a459900ca987f193'},'EoP','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2' : 'https://android.googlesource.com/platform/system/core/+/46d46dc46446f14f26fbe8fb102dd36c1dfc1229'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01','None'],
                    
                    ['01', 'CVE-2024-0035','A-300903792',{'A-300903792': 'https://android.googlesource.com/platform/frameworks/base/+/7b7fff1eb5014d12200a32ff9047da396c7ab6a4'},'EoP','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2023-40093','A-279055389',{'A-279055389': 'https://android.googlesource.com/platform/external/pdfium/+/03925281cf25fec70318bf2225356d022b12b566'},'ID','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2' : 'https://android.googlesource.com/platform/cts/+/a952c93009cc81c41a086d73a4030a83b7683a04'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['01', 'CVE-2024-0030','A-276898739',{'A-276898739': 'https://android.googlesource.com/platform/packages/modules/Bluetooth/+/57b823f4f758e2ef530909da07552b5aa80c6a7d'},'ID','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-5091','A-298150556','None','None','High','None','Arm components', 'Mali', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-5249','A-301630648','None','None','High','None','Arm components', 'Mali', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-5643','A-308188986','None','None','High','None','Arm components', 'Mali', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2024-20011','A-314698315','None','None','High','None','MediaTek components', 'alac decoder', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08441146'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2024-20006','A-314707751','None','None','High','None','MediaTek components', 'DA', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08477148'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2024-20007','A-314698312','None','None','High','None','MediaTek components', 'mp3 decoder', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08441369'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2024-20009','A-314698313','None','None','High','None','MediaTek components', 'alac decoder', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08441150'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2024-20010','A-314698314','None','None','High','None','MediaTek components', 'keyInstall', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-ALPS08358560'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-32841','A-317829109','None','None','High','None','MediaTek components', '5G Modem', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-MOLY01128524'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-32842','A-317826159','None','None','High','None','MediaTek components', '5G Modem', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-MOLY01130256'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-32843','A-317829110','None','None','High','None','MediaTek components', '5G Modem', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-MOLY01130204'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2024-20003','A-317829112','None','None','High','None','MediaTek components', '5G Modem', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['M-MOLY01191612'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-49667','A-314033392','None','None','High','None','Unisoc components', 'Kernel', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['U-2455269'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-49668','A-314032846','None','None','High','None','Unisoc components', 'Kernel', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', ['U-2455269'], 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43513','A-303101658','None','None','High','None','Qualcomm components', 'Kernel', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['QC-CR#3545432', '[2]'], {'QC-CR#3545432' : 'https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/74b921d47b4e80adb9d115df1ca171ba8c23a8c1', '2': 'https://git.codelinaro.org/clo/la/kernel/msm-5.15/-/commit/fb76c39fe1a0272d40942dfdeba5b471b0b643b4'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43516','A-309461150','None','None','High','None','Qualcomm components', 'Video', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['QC-CR#3536092'], {'QC-CR#3536092' : 'https://git.codelinaro.org/clo/la/platform/vendor/opensource/video-driver/-/commit/e21682f825e909a4389bee60bcd1768423aede97'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01','None'],
                    
                    ['05', 'CVE-2023-43520','A-309461173','None','None','High','None','Qualcomm components', 'WLAN', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['QC-CR#3575335'], {'QC-CR#3575335' : 'https://git.codelinaro.org/clo/la/platform/vendor/qcom-opensource/wlan/qcacld-3.0/-/commit/f92388d27db9a17230035b5e1bf5eb48c546b305'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43534','A-309461218','None','None','High','None','Qualcomm components', 'WLAN', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['QC-CR#3575491', 'QC-CR#3578829'], {'QC-CR#3575491' : 'https://git.codelinaro.org/clo/la/platform/vendor/qcom-opensource/wlan/qcacld-3.0/-/commit/1b5a78038619597643bb0e7ab05d6bbcab522e5e', 'QC-CR#3578829' : 'https://git.codelinaro.org/clo/la/platform/vendor/qcom-opensource/wlan/qcacld-3.0/-/commit/3bc1dd9b5ffe6b0f876111c7ae2bd8dcc22bd7ee'}, '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33046','A-295038516','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33049','A-295039556','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33057','A-295039728','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33058','A-295038658','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33060','A-295039022','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33072','A-295038660','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-33076','A-295039588','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43518','A-309460837','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43519','A-309461083','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43522','A-309461138','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43523','A-309460866','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43533','A-309461430','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
                    
                    ['05', 'CVE-2023-43536','A-309461332','None','None','High','None','Qualcomm closed-source components', 'Closed-source component', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'True', 'Android OS', 'None', 'None', '2024-02', 'https://source.android.com/docs/security/bulletin/2024-02-01', 'None'],
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2024-02-01", "2024-02")

        file_container.clean_files()
        
        for result_row, expected_row in zip(file_container.get_files()[0][:], expected):

            self.assertEqual(expected_row, result_row)
            
        
    '''
    Test when there is a cve without a reference code
    '''    
    def test_january(self):
        expected = [
                ['01', 'CVE-2023-21245','A-222446076',{'A-222446076': 'https://android.googlesource.com/platform/frameworks/base/+/a33159e8cb297b9eee6fa5c63c0e343d05fad622'},'EoP','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2' : 'https://android.googlesource.com/platform/frameworks/base/+/d42f8d774901e8bcdf2c83b61b01fad79ce2f69f'}, '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0015','A-300090204',{'A-300090204': 'https://android.googlesource.com/platform/frameworks/base/+/2ce1b7fd37273ea19fbbb6daeeaa6212357b9a70'},'EoP','High','11, 12, 12L, 13','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0018','A-300476626',{'A-300476626': 'https://android.googlesource.com/platform/frameworks/av/+/bf6406041919f67219fd1829438dda28845d4c23'},'EoP','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0023','A-283099444',{'A-283099444': 'https://android.googlesource.com/platform/frameworks/av/+/30b1b34cfd5abfcfee759e7d13167d368ac6c268'},'EoP','High','11, 12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2' : 'https://android.googlesource.com/platform/frameworks/av/+/30b1b34cfd5abfcfee759e7d13167d368ac6c268'}, '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0019','A-294104969',{'A-294104969': 'https://android.googlesource.com/platform/frameworks/base/+/707fc94ec3df4cf6b985e6d06c2588690d1a025a'},'ID','High','12, 12L, 13, 14','Framework', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0021','A-282934003',{'A-282934003': 'https://android.googlesource.com/platform/packages/apps/Settings/+/53ea491d276f9a7c586c7983c08105a9bb7051f1'},'EoP','High','13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2023-40085','A-269271098',{'A-269271098': 'https://android.googlesource.com/platform/packages/modules/NeuralNetworks/+/ed6ee1f7eca7b33160e36ac6d730a9ef395ca4f1'},'ID','High','12, 12L, 13','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0016','A-279169188',{'A-279169188': 'https://android.googlesource.com/platform/packages/modules/Bluetooth/+/1d7ba7c8a205522f384e8d5c7c9f26a421cab5f1'},'ID','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', ['[2]'], {'2' : 'https://android.googlesource.com/platform/packages/modules/Bluetooth/+/1d7ba7c8a205522f384e8d5c7c9f26a421cab5f1'}, '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0017','A-285142084',{'A-285142084': 'https://android.googlesource.com/platform/packages/apps/Camera2/+/5c4c4b35754eef319dcd69c422f0b1ac0c823f6e'},'ID','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0020','A-299614635',{'A-299614635': 'https://android.googlesource.com/platform/packages/apps/Settings/+/87f791f2351e366f842a0fd6fcb744069160d9a1'},'ID','High','11, 12, 12L, 13, 14','System', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None'],
                
                ['01', 'CVE-2024-0018','None','None','None','None','None','Google Play system updates', 'Media Codecs', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 'False', 'Android OS', 'None', 'None', '2024-01', 'https://source.android.com/docs/security/bulletin/2024-01-01', 'None']
        ]
        
        file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2024-01-01", "2024-01")

        file_container.clean_files()
        
        for result_row, expected_row in zip(file_container.get_files()[0][:11], expected):
            self.assertEqual(expected_row, result_row)
            
            
if __name__ == '__main__':
    unittest.main()