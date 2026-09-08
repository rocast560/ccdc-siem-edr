import re
rx = re.compile(r'(?i)(mshta(\.exe)?\s+\S+:|wscript(\.exe)?\"?\s+\"?\S+\.(vbs|js)|cscript(\.exe)?\"?\s+\"?\S+\.(vbs|js)|wmic(\.exe)?\s+.*/format:\"?http)')
cases = [
    r'"C:\Windows\System32\wscript.exe" C:\Users\Public\ccdc_stager_test.vbs',
    'wscript.exe stager.vbs',
    'cscript C:\\x\\y.js',
    r'notepad.exe readme.txt',
]
for c in cases:
    print(bool(rx.search(c)), c)
