# Publishing delta updates

The first delta-capable release is wisp.6 (4000756). Older clients ignore the
optional deltas field and download the full APK. Never overwrite a published
versionCode or APK; retain historical base assets.

Generate a smaller patch, replayed automatically by the generator:

    python3 tools/wisp_delta.py --base old-signed.apk --target new-signed.apk --output Wisp-from-old.wdelta

Add deltas (up to eight) inside the relevant assets[abi] object in schema v1:

    {
      "format": "wisp-zip-delta-v1",
      "baseVersionCode": 4000756,
      "baseSizeBytes": <exact old APK bytes>,
      "baseSha256": "<old APK SHA-256>",
      "baseUrl": "https://github.com/MadStickers/wisp-updates/releases/download/<old-tag>/<old>.apk",
      "url": "https://github.com/MadStickers/wisp-updates/releases/download/<new-tag>/<patch>.wdelta",
      "sizeBytes": <exact patch bytes>,
      "sha256": "<patch SHA-256>"
    }

Always attach the full signed APK, source.zip, preview.json and every named patch.
The updated publisher requires wisp_delta.py and both test modules. Run
python3 -m unittest discover -s tools. The workflow validates and replays every
advertised delta against the exact signed target before publishing the channel.

Format: ASCII WISPDLT1, big-endian base/target uint64 sizes, 32-byte SHA-256 for
each, uint32 instruction count. COPY opcode 0: uint64 offset, uint32 length.
LITERAL opcode 1: uint32 raw length, uint32 compressed length, one zlib stream.
No trailing bytes. APKs <=150 MiB; operations <=100,000; each literal <=1 MiB raw
and <=1 MiB+1024 compressed. The phone never decompresses ZIP archive entries.
