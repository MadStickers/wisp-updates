import base64
import copy
import json
import os
import unittest
from unittest.mock import patch
import publish_preview as publisher

TAG = 'preview-v5'
URL = 'https://github.com/MadStickers/wisp-updates/releases/download/' + TAG + '/Wisp.apk'


def manifest():
    return dict(schemaVersion=1, channel='preview', packageName=publisher.PACKAGE,
                signingCertSha256=publisher.CERT, versionCode=4000755, versionName='wisp.5',
                minSdk=24, notes='Notes', assets={'arm64-v8a': dict(url=URL, sizeBytes=3, sha256='a' * 64)})


class PreviewPublisherTest(unittest.TestCase):
    def test_identity_versions_and_release_urls_are_checked(self):
        self.assertEqual(publisher.validate_manifest(manifest(), TAG), manifest())
        changes = [('schemaVersion', True), ('channel', 'legacy'), ('packageName', 'com.v2ray.ang'),
                   ('signingCertSha256', 'b' * 64), ('versionCode', -1), ('versionCode', 1.5),
                   ('versionName', ''), ('versionName', 'a' * 81)]
        for key, value in changes:
            data = manifest()
            data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                publisher.validate_manifest(data, TAG)
        for key, value in [('sizeBytes', publisher.MAX_BYTES + 1), ('sha256', 'bad'),
                           ('url', URL.replace('https:', 'http:')), ('url', URL.replace(TAG, 'legacy'))]:
            data = manifest()
            data['assets']['arm64-v8a'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                publisher.validate_manifest(data, TAG)

    def run_publish(self, current=None, invalid_apk=False):
        data = manifest()
        calls = []
        release = dict(draft=False, prerelease=True, assets=[
            dict(name='preview.json', state='uploaded', browser_download_url='manifest'),
            dict(name='Wisp-source.zip', state='uploaded', browser_download_url='source'),
            dict(name='Wisp.apk', state='uploaded', browser_download_url=URL)])

        def api(path, token, method='GET', body=None):
            calls.append((path, method, body))
            if path.startswith('releases/'):
                return release
            if method == 'GET':
                return dict(sha='existing-file', content=base64.b64encode(json.dumps(current).encode()).decode())
            return dict(commit=dict(sha='new-file'))

        def public(url, limit):
            return json.dumps(data).encode() if url == 'manifest' else b'apk'

        with patch.dict(os.environ, GITHUB_REPOSITORY=publisher.REPO, GITHUB_TOKEN='fixture'), \
                patch.object(publisher, 'api', side_effect=api), \
                patch.object(publisher, 'public_bytes', side_effect=public), \
                patch.object(publisher, 'validate_apk', side_effect=ValueError('wrong APK') if invalid_apk else None):
            try:
                publisher.publish(TAG, '/fixture-sdk')
                return calls, None
            except ValueError as error:
                return calls, error

    def test_failed_apk_verification_never_updates_channel(self):
        calls, error = self.run_publish(manifest(), invalid_apk=True)
        self.assertIsNotNone(error)
        self.assertFalse(any(method == 'PUT' for _, method, _ in calls))

    def test_existing_version_is_idempotent(self):
        calls, error = self.run_publish(manifest())
        self.assertIsNone(error)
        self.assertFalse(any(method == 'PUT' for _, method, _ in calls))

    def test_channel_cannot_roll_back_or_silently_replace_an_existing_version(self):
        higher = manifest()
        higher['versionCode'] += 1
        changed = copy.deepcopy(manifest())
        changed['assets']['arm64-v8a']['sha256'] = 'b' * 64
        for old in [higher, changed]:
            calls, error = self.run_publish(old)
            self.assertIsNotNone(error)
            self.assertFalse(any(method == 'PUT' for _, method, _ in calls))

    def test_newer_verified_release_uses_the_current_blob_sha(self):
        older = manifest()
        older['versionCode'] -= 1
        calls, error = self.run_publish(older)
        self.assertIsNone(error)
        writes = [body for _, method, body in calls if method == 'PUT']
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]['sha'], 'existing-file')
        self.assertEqual(json.loads(base64.b64decode(writes[0]['content'])), manifest())


if __name__ == '__main__':
    unittest.main()
