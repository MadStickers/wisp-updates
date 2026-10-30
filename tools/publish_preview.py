#!/usr/bin/env python3
"""Validate pre-signed release assets before promoting the Wisp Preview update channel."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

REPO = 'MadStickers/wisp-updates'
PACKAGE = 'com.wispvpn.preview'
CERT = 'c74f66317749335ca16e4e6e8feb5fe1787aa3e2334efbe3130d9ac430266f88'
MAX_BYTES = 150 * 1024 * 1024
ABIS = {'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'}


def validate_manifest(meta, tag):
    if type(meta.get('schemaVersion')) is not int or meta['schemaVersion'] != 1 or meta.get('channel') != 'preview':
        raise ValueError('Not a Preview schema v1 manifest')
    if meta.get('packageName') != PACKAGE or meta.get('signingCertSha256') != CERT:
        raise ValueError('Wrong Preview package/signing identity')
    for key, lo, hi in [('versionCode', 1, 2147483647), ('minSdk', 24, 2147483647)]:
        value = meta.get(key)
        if type(value) is not int or not lo <= value <= hi:
            raise ValueError('Invalid ' + key)
    if not isinstance(meta.get('versionName'), str) or not meta['versionName'].strip() or len(meta['versionName']) > 80:
        raise ValueError('Invalid versionName')
    if not isinstance(meta.get('notes', ''), str) or len(meta.get('notes', '')) > 4000:
        raise ValueError('Invalid release notes')
    assets = meta.get('assets')
    if not isinstance(assets, dict) or not assets or not set(assets) <= ABIS:
        raise ValueError('Invalid ABI assets')
    for abi, asset in assets.items():
        if type(asset.get('sizeBytes')) is not int or not 1 <= asset['sizeBytes'] <= MAX_BYTES:
            raise ValueError('Invalid APK size')
        if not re.fullmatch('[0-9a-f]{64}', asset.get('sha256', '')):
            raise ValueError('Invalid APK SHA-256')
        url = urllib.parse.urlsplit(asset.get('url', ''))
        prefix = '/' + REPO + '/releases/download/' + tag + '/'
        if (url.scheme != 'https' or url.netloc != 'github.com' or url.query or url.fragment or
                not url.path.startswith(prefix) or '/' in url.path[len(prefix):] or
                '%' in url.path or not url.path.endswith('.apk') or '/..' in url.path):
            raise ValueError('APK URL must be a versioned asset in this Preview release')
    return meta


def validate_apk(meta, abi, apk, sdk):
    asset = meta['assets'][abi]
    if apk.stat().st_size != asset['sizeBytes'] or hashlib.sha256(apk.read_bytes()).hexdigest() != asset['sha256']:
        raise ValueError('APK size/checksum mismatch')
    tools = Path(sdk) / 'build-tools' / '37.0.0'
    verified = subprocess.check_output([str(tools / 'apksigner'), 'verify', '--print-certs', str(apk)], text=True)
    digests = set(re.findall(r'certificate SHA-256 digest: ([a-f0-9]+)', verified))
    if digests != {CERT}:
        raise ValueError('Unexpected APK signing key')
    badging = subprocess.check_output([str(tools / 'aapt'), 'dump', 'badging', str(apk)], text=True)
    package = re.search(r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging, re.M)
    sdk_version = re.search(r"^sdkVersion:'(\d+)'", badging, re.M)
    native = re.search(r'^native-code: (.+)$', badging, re.M)
    if (not package or package[1] != PACKAGE or int(package[2]) != meta['versionCode'] or
            package[3] != meta['versionName'] or not sdk_version or int(sdk_version[1]) != meta['minSdk'] or
            not native or "'" + abi + "'" not in native[1]):
        raise ValueError('APK package, version, minimum SDK or ABI does not match the manifest')


def public_bytes(url, limit):
    with urllib.request.urlopen(url, timeout=120) as response:
        if urllib.parse.urlsplit(response.url).scheme != 'https':
            raise ValueError('Insecure release redirect')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Release asset exceeds its size limit')
    return data


def api(path, token, method='GET', body=None):
    request = urllib.request.Request('https://api.github.com/repos/' + REPO + '/' + path,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'},
        method=method, data=None if body is None else json.dumps(body).encode())
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def publish(tag, sdk):
    if os.environ.get('GITHUB_REPOSITORY') != REPO or not tag.startswith('preview-') or '/' in tag:
        raise ValueError('Unexpected release repository/tag')
    token = os.environ['GITHUB_TOKEN']
    release = api('releases/tags/' + urllib.parse.quote(tag, safe=''), token)
    if release['draft'] or not release['prerelease']:
        raise ValueError('Publish Preview as a prerelease to preserve the legacy latest channel')
    assets = {item['name']: item for item in release['assets'] if item['state'] == 'uploaded'}
    if 'preview.json' not in assets or not any(name.endswith('source.zip') for name in assets):
        raise ValueError('Attach preview.json, APK and corresponding source.zip before publishing')
    meta = validate_manifest(json.loads(public_bytes(assets['preview.json']['browser_download_url'], 65536)), tag)
    with tempfile.TemporaryDirectory() as directory:
        for abi, entry in meta['assets'].items():
            name = urllib.parse.urlsplit(entry['url']).path.rsplit('/', 1)[-1]
            if name not in assets or assets[name]['browser_download_url'] != entry['url']:
                raise ValueError('APK is not attached to this release')
            apk = Path(directory) / (abi + '.apk')
            apk.write_bytes(public_bytes(entry['url'], entry['sizeBytes']))
            validate_apk(meta, abi, apk, sdk)
    path = 'contents/channels/preview.json'
    current = None
    try:
        current = api(path + '?ref=main', token)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    if current:
        old = json.loads(base64.b64decode(current['content']))
        if old['versionCode'] > meta['versionCode']:
            raise ValueError('Refusing to roll back the Preview channel')
        if old['versionCode'] == meta['versionCode']:
            if old != meta:
                raise ValueError('A published version cannot be silently replaced; bump versionCode')
            print('Preview channel is already current')
            return
    body = {'message': 'Publish verified Wisp Preview ' + meta['versionName'], 'branch': 'main',
            'content': base64.b64encode((json.dumps(meta, ensure_ascii=False, indent=2) + '\n').encode()).decode()}
    if current:
        body['sha'] = current['sha']
    result = api(path, token, 'PUT', body)
    print('Preview channel updated at commit ' + result['commit']['sha'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--apk', type=Path)
    parser.add_argument('--tag', default=os.environ.get('WISP_RELEASE_TAG'))
    parser.add_argument('--sdk', default=os.environ.get('ANDROID_HOME'))
    args = parser.parse_args()
    if not args.tag or not args.sdk:
        parser.error('tag and Android SDK are required')
    if args.manifest or args.apk:
        if not (args.manifest and args.apk):
            parser.error('pass both --manifest and --apk for a local validation')
        meta = validate_manifest(json.loads(args.manifest.read_text()), args.tag)
        if len(meta['assets']) != 1:
            parser.error('local single-APK check expects one ABI')
        validate_apk(meta, next(iter(meta['assets'])), args.apk, args.sdk)
        print('Preview manifest, APK identity, signature and checksum verified')
    else:
        publish(args.tag, args.sdk)
