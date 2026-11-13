"""Validate shipping translations, format arguments and English source policy."""
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENTRY = re.compile(r'^\s*("(?:[^"\\]|\\.)*")\s*=\s*("(?:[^"\\]|\\.)*")\s*;', re.M)
ARGUMENT = re.compile(r'%(?:[1-9][0-9]*\$)?(?:@|[diuoxXfFeEgGcs])')


def strings(language):
    path = ROOT / 'Resources' / (language + '.lproj') / 'Localizable.strings'
    pairs = [(json.loads(key), json.loads(value)) for key, value in ENTRY.findall(path.read_text())]
    assert len(pairs) == len(dict(pairs)), 'Duplicate localization keys: ' + language
    parsed = json.loads(subprocess.check_output(['/usr/bin/plutil', '-convert', 'json', '-o', '-', str(path)]))
    assert parsed == dict(pairs), 'Unparsed localization entries: ' + language
    return parsed


english, chinese = strings('en'), strings('zh-Hans')
assert english.keys() == chinese.keys(), 'Localization key sets differ'
for key in english:
    assert english[key] and chinese[key], 'Empty translation: ' + key
    assert sorted(ARGUMENT.findall(english[key])) == sorted(ARGUMENT.findall(chinese[key])), 'Format arguments differ: ' + key
for source in sorted((ROOT / 'Sources').glob('*.swift')):
    text = source.read_text()
    assert not re.search(r'[\u3400-\u9fff]', text), 'Non-English source text: ' + source.name
    for literal in re.findall(r'(?:GuardText|\btr)\("((?:[^"\\]|\\.)*)"', text):
        try:
            key = json.loads('"' + literal + '"')
        except ValueError:  # Swift interpolation is checked at its literal leaves.
            continue
        assert key in english, 'Missing shipping translation: ' + key
for language in ('en', 'zh-Hans'):
    conclusion = (ROOT / 'Installer' / 'Resources' / (language + '.lproj') / 'Conclusion.html').read_text()
    assert 'IPQS' not in conclusion, 'Obsolete required-key instructions: ' + language
print('PASS: bilingual key coverage, unique entries, format arguments, English source and automatic installer guidance')
