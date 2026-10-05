#!/usr/bin/env python3
# Copyright (c) 2026 m7.org; License: MTL-10 (see LICENSE.md)
"""Exercise encrypted UDP auth dispatch with temporary keys and a marker hook.

Run: python3 tests/auth_dispatch.py [--openssl-prefix /usr/local/openssl-3.0]
The fixture copies tracked source, adapts config/bind paths only, and builds
in a temporary directory. It never opens a production config or sends remotely.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def command(args, **kwargs):
    try:
        return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, **kwargs)
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr.decode(errors='replace'), file=sys.stderr)
        raise


def labels(path):
    return path.read_text().splitlines() if path.exists() else []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-prefix', type=Path)
    parser.add_argument('--keep', action='store_true', help='retain fixture logs and receipt')
    opts = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    fixture = Path(tempfile.mkdtemp(prefix='siglatch-auth-dispatch-'))
    os.chmod(str(fixture), 0o700)
    os.umask(0o077)
    passed = False
    daemon = None
    output = None
    try:
        tracked = command(['git', '-C', str(repo), 'ls-files', '-z']).stdout.split(b'\0')
        for name in tracked:
            if not name:
                continue
            relative = Path(os.fsdecode(name))
            source = repo / relative
            if source.is_file():
                dest = fixture / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(source), str(dest))
        source_hash = hashlib.sha256((fixture / 'src/siglatch/handle_packet.c').read_bytes()).hexdigest()
        main_file = fixture / 'src/siglatch/main.c'
        text = main_file.read_text()
        needle = 'lib.config.load("/etc/siglatch/server.conf");'
        assert text.count(needle) == 1, 'Unexpected config loader; refusing fixture changes'
        main_file.write_text(text.replace(needle, 'lib.config.load("' + str(fixture / 'server.conf') + '");'))
        listener = fixture / 'src/siglatch/udp_listener.c'
        text = listener.read_text()
        needle = 'server.sin_addr.s_addr = INADDR_ANY;'
        assert text.count(needle) == 1, 'Unexpected listener; refusing fixture changes'
        listener.write_text(text.replace(needle, 'server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);'))

        prefix = opts.openssl_prefix
        openssl = str(prefix / 'bin/openssl') if prefix else shutil.which('openssl')
        if not prefix and Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists():
            openssl = '/opt/homebrew/opt/openssl@3/bin/openssl'
        assert openssl, 'OpenSSL command not found'
        build_args = ['make', 'all']
        openssl_env = os.environ.copy()
        if prefix:
            libdir = prefix / ('lib64' if (prefix / 'lib64').is_dir() else 'lib')
            build_args += ['OPENSSL_CFLAGS=-I' + str(prefix / 'include'),
                           'OPENSSL_LDFLAGS=-L' + str(libdir) + ' -Wl,-rpath,' + str(libdir)]
            # A custom OpenSSL executable may lack the rpath used by our build.
            previous = openssl_env.get('LD_LIBRARY_PATH', '')
            openssl_env['LD_LIBRARY_PATH'] = str(libdir) + (os.pathsep + previous if previous else '')
        built = command(build_args, cwd=str(fixture))
        (fixture / 'build.log').write_bytes(built.stdout + built.stderr)
        command([openssl, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                 '-out', str(fixture / 'private.pem')], env=openssl_env)
        command([openssl, 'pkey', '-in', str(fixture / 'private.pem'), '-pubout',
                 '-out', str(fixture / 'public.pem')], env=openssl_env)
        (fixture / 'hmac.key').write_bytes(os.urandom(32))
        (fixture / 'wrong.key').write_bytes(os.urandom(32))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        marker_file = fixture / 'markers.log'
        marker_script = fixture / 'marker.pl'
        marker_script.write_text('use strict; use warnings; use MIME::Base64 qw(decode_base64);\n'
            'open my $f, ">>", "' + str(marker_file) + '" or die $!;\n'
            'print $f decode_base64($ARGV[6]), "\\n"; close $f;\n')
        (fixture / 'server.conf').write_text('''log_file = {root}/daemon.log
priv_key_path = {root}/private.pem
[server:secure]
enabled = yes
secure = yes
port = {port}
priv_key_path = {root}/private.pem
log_file = {root}/daemon.log
logging = yes
actions = marker
[action:marker]
id = 42
enabled = yes
constructor = /usr/bin/perl {root}/marker.pl
exec_split = 1
[user:test]
id = 1
enabled = yes
key_file = {root}/public.pem
hmac_file = {root}/hmac.key
actions = marker
'''.format(root=fixture, port=port))
        output = open(str(fixture / 'daemon.stdout.log'), 'wb')
        daemon = subprocess.Popen([str(fixture / 'siglatchd')], cwd=str(fixture),
                                  stdout=output, stderr=output)

        def send(label, key='hmac.key', extra=None):
            args = [str(fixture / 'knocker'), '--port', str(port), '--server-key',
                    str(fixture / 'public.pem'), '--hmac-key', str(fixture / key)]
            sent = command(args + (extra or []) + ['127.0.0.1', '1', '42', label], input=b'')
            (fixture / (label + '.client.log')).write_bytes(sent.stdout + sent.stderr)

        # A harmless valid marker confirms readiness; fresh nonces allow retry
        # if an initial UDP packet was sent before the listener bound.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and 'VALID_BEFORE' not in labels(marker_file):
            assert daemon.poll() is None, 'Daemon exited during startup'
            send('VALID_BEFORE')
            time.sleep(0.2)
        assert 'VALID_BEFORE' in labels(marker_file), 'Valid request did not execute'
        send('DUMMY_HMAC', extra=['--dummy-hmac'])
        send('WRONG_KEY', key='wrong.key')
        send('NO_HMAC', extra=['--no-hmac'])
        send('VALID_AFTER')
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and 'VALID_AFTER' not in labels(marker_file):
            time.sleep(0.05)
        assert 'VALID_AFTER' in labels(marker_file), 'Daemon failed to process a later valid request'
        daemon.terminate()
        daemon.wait(timeout=8)
        output.close()
        output = None
        log = (fixture / 'daemon.log').read_text(errors='replace')
        assert log.count('Signature mismatch for user_id 1') == 3, 'Not all invalid HMACs were processed'
        assert log.count('invalid signature') == 3, 'Not all invalid HMACs reached rejection guard'
        executed = labels(marker_file)
        assert set(executed) == {'VALID_BEFORE', 'VALID_AFTER'}, 'Invalid request invoked constructor: ' + repr(executed)
        receipt = {'source_commit': command(['git', '-C', str(repo), 'rev-parse', 'HEAD']).stdout.decode().strip(),
                   'handler_sha256': source_hash, 'bind_address': '127.0.0.1', 'port': port,
                   'valid_before_executed': True, 'valid_after_executed': True,
                   'dummy_hmac_executed': False, 'wrong_key_executed': False,
                   'no_hmac_executed': False, 'rejected_signature_count': 3,
                   'daemon_stopped': daemon.poll() is not None,
                   'openssl': command([openssl, 'version'], env=openssl_env).stdout.decode().strip()}
        (fixture / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print('PASS: valid requests execute before/after three invalid signatures; all invalid requests rejected.')
        passed = True
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=8)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
        if output is not None:
            output.close()
        if passed and not opts.keep:
            shutil.rmtree(str(fixture))
        else:
            print('Fixture and receipt: ' + str(fixture))


if __name__ == '__main__':
    main()
