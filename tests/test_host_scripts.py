"""Offline regressions: all transports and Android commands are inert mocks."""
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'

# ssh interprets the command using a real POSIX shell, but that shell's PATH
# contains only inert mocks. adb records arguments and never executes Android
# commands. Even a quoting regression cannot launch a transport or payload.
MOCK = r'''
import json, os, subprocess, sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_LOG'], 'a') as stream:
    stream.write(json.dumps({'name': name, 'args': args}) + '\n')
if name == 'ssh':
    if args and args[0] == '--': args = args[1:]
    command = ' '.join(args[1:])
    failure = os.environ.get('MOCK_SSH_FAIL_MATCH')
    if failure and failure in command: sys.exit(255)
    env = dict(os.environ, PATH=os.environ['MOCK_REMOTE_BIN'])
    sys.exit(subprocess.run(['/bin/sh', '-c', command], env=env).returncode)
if name == 'scp': sys.exit(int(os.environ.get('MOCK_SCP_RC', '0')))
if name == 'sleep': sys.exit(0)
if name != 'adb':
    print('diagnostic escaped to bridge: ' + name, file=sys.stderr)
    sys.exit(97)
if args[:2] != ['-s', os.environ['SERIAL']]: sys.exit(96)
failure = os.environ.get('MOCK_ADB_FAIL_MATCH')
if failure and failure in ' '.join(args): sys.exit(74)
action = args[2]
if action == 'get-state':
    print('device')
elif action == 'push':
    sys.exit(int(os.environ.get('MOCK_PUSH_RC', '0')))
elif action in ('shell', 'exec-out'):
    if len(args) != 4:
        print('Android command was split into bridge arguments', file=sys.stderr)
        sys.exit(95)
    command = args[3]
    # Parse only: this never evaluates an Android command or substitution.
    if subprocess.run(['/bin/sh', '-n', '-c', command]).returncode: sys.exit(94)
    if command.startswith('chmod '):
        sys.exit(int(os.environ.get('MOCK_CHMOD_RC', '0')))
    if command.startswith('/data/local/tmp/dc '):
        print('fixture cache-write diagnostic')
        sys.exit(int(os.environ.get('MOCK_DC_RC', '0')))
    if action == 'exec-out':
        data = Path(os.environ['MOCK_PAYLOAD']).read_bytes()
        mode = os.environ.get('MOCK_READ_KIND', 'matching')
        if mode == 'short': data = data[:-1]
        if mode == 'mismatch': data = bytes([data[0] ^ 1]) + data[1:]
        sys.stdout.buffer.write(data)
    else:
        print('fixture Android diagnostic')
else:
    sys.exit(93)
'''


class HostScripts(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='z580ca-host-')
        self.addCleanup(self.scratch.cleanup)
        self.work = Path(self.scratch.name)
        self.transport = self.work / 'transport'
        self.remote = self.work / 'remote'
        self.transport.mkdir()
        self.remote.mkdir()
        for directory, names in (
            (self.transport, ('ssh', 'scp', 'sleep')),
            (self.remote, ('adb', 'ps', 'getprop', 'getenforce', 'cat', 'ls',
                           'dd', 'dmesg', 'grep', 'cut', 'tr', 'tail')),
        ):
            for name in names:
                target = directory / name
                target.write_text('#!' + sys.executable + '\n' + MOCK)
                target.chmod(0o700)
        self.payload = self.work / 'payload fixture'
        self.payload.write_bytes(b'fixture payload\x00with\r\nbinary bytes\xff')
        self.log = self.work / 'commands.jsonl'
        ambient = {key: value for key, value in os.environ.items()
                   if not key.startswith('MOCK_') and key not in ('BASH_ENV', 'ENV',
                                                                'PYTHONPATH', 'PYTHONHOME')}
        self.env = dict(ambient, PATH=str(self.transport) + os.pathsep + os.defpath,
                        BRIDGE='fixture_user@fixture_bridge', SERIAL='fixture:5555',
                        MOCK_LOG=str(self.log), MOCK_PAYLOAD=str(self.payload),
                        MOCK_REMOTE_BIN=str(self.remote), TMPDIR=str(self.work))

    def invoke(self, script='update-cached-payload.sh', **env):
        args = ['/bin/bash', str(SCRIPTS / script)]
        if script == 'update-cached-payload.sh':
            args += [str(self.payload), '0']
        return subprocess.run(args, cwd=self.work, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=15)

    def calls(self):
        if not self.log.exists(): return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def android_commands(self):
        return [call['args'] for call in self.calls() if call['name'] == 'adb']

    def assert_no_cache_write(self):
        self.assertFalse(any('/data/local/tmp/dc ' in ' '.join(args)
                             for args in self.android_commands()))

    def test_matching_binary_cache_prefix_succeeds(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any('/data/local/tmp/dc ' in ' '.join(args)
                            for args in self.android_commands()))
        self.assertIn('== recent avc ==', result.stdout)

    def test_failed_scp_never_pushes_or_writes_cache(self):
        result = self.invoke(MOCK_SCP_RC='71')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.android_commands(), [])

    def test_failed_push_never_invokes_cache_writer(self):
        result = self.invoke(MOCK_PUSH_RC='71')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_cache_write()

    def test_failed_chmod_never_invokes_cache_writer(self):
        result = self.invoke(MOCK_CHMOD_RC='72')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_cache_write()

    def test_failed_cache_write_is_not_hidden_by_tail(self):
        result = self.invoke(MOCK_DC_RC='73')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(args[2] == 'exec-out' for args in self.android_commands()))

    def test_zero_status_cache_write_still_requires_matching_bytes(self):
        for kind in ('mismatch', 'short'):
            with self.subTest(kind=kind):
                result = self.invoke(MOCK_READ_KIND=kind)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('cache verification failed', result.stderr)
                self.assertNotIn('== wait', result.stdout)

    def test_updater_transport_failures_propagate(self):
        for stage in ("'push'", "'exec-out'", 'getprop |'):
            with self.subTest(stage=stage):
                result = self.invoke(MOCK_SSH_FAIL_MATCH=stage)
                self.assertNotEqual(result.returncode, 0)

    def test_inspector_keeps_compound_commands_on_android(self):
        result = self.invoke('inspect-unlock-state.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.android_commands())
        for call in self.calls():
            self.assertIn(call['name'], ('ssh', 'adb'))
        for args in self.android_commands():
            if args[2] in ('shell', 'exec-out'):
                self.assertEqual(len(args), 4)
        self.assertTrue(any('for N in 4' in args[-1] for args in self.android_commands()))
        self.assertTrue(any('$(ps |' in args[-1] for args in self.android_commands()))
        self.assertTrue(any('getprop sys.oem_unlock_allowed;' in args[-1]
                            for args in self.android_commands()))

    def test_inspector_transport_failures_propagate(self):
        for stage in ("'get-state'", "'exec-out'", 'getenforce'):
            with self.subTest(stage=stage):
                result = self.invoke('inspect-unlock-state.sh', MOCK_SSH_FAIL_MATCH=stage)
                self.assertNotEqual(result.returncode, 0)

    def test_optional_diagnostic_does_not_hide_adb_connection_failure(self):
        for script, marker in (('inspect-unlock-state.sh', 'getenforce'),
                               ('update-cached-payload.sh', 'getprop |')):
            with self.subTest(script=script):
                result = self.invoke(script, MOCK_ADB_FAIL_MATCH=marker)
                self.assertNotEqual(result.returncode, 0)

    def test_unsafe_connection_settings_fail_before_transport(self):
        for script in ('inspect-unlock-state.sh', 'update-cached-payload.sh'):
            for setting, value in (('BRIDGE', '-oProxyCommand=anything'),
                                   ('BRIDGE', 'host; echo injected'),
                                   ('SERIAL', "serial' ; echo injected")):
                with self.subTest(script=script, setting=setting):
                    result = self.invoke(script, **{setting: value})
                    self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_helper_preserves_quotes_substitutions_and_newlines(self):
        command = "printf '%s\\n' \"literal $(anything); 'quote'\"\necho done"
        result = subprocess.run(
            ['/bin/bash', '-euc',
             'source "$1"; adb_host_validate; adb_host shell "$2"',
             'fixture', str(SCRIPTS / 'lib/adb-host.sh'), command],
            cwd=self.work, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.android_commands(), [['-s', self.env['SERIAL'], 'shell', command]])


class DroidbootPointerBounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Python reads reference bytes; it never executes the bundled ELF.
        cls.index = runpy.run_path(str(ROOT / 'tools/droidboot/disassembly_index.py'))

    def synthetic_mapping(self):
        data = bytearray(24)
        for offset in (0, 4, 8, 16, 20):
            struct.pack_into('<I', data, offset, 0x1000)
        return patch.dict(self.index['data_ptrs'].__globals__, {
            'LOAD_SEGMENTS': ((0x1000, 0, 8), (0x2000, 16, 8)),
            '_raw': bytes(data), 'strings': {0x1000: 'fixture string'},
        })

    def test_default_scan_has_only_mapped_virtual_addresses(self):
        pointers = self.index['data_ptrs']()
        self.assertTrue(pointers)
        self.assertNotIn(None, pointers)
        sorted(pointers)
        self.assertTrue(all(0x1a3200 <= address < 0x1ae200 for address in pointers))

    def test_virtual_bounds_convert_once_and_skip_unmapped_bytes(self):
        with self.synthetic_mapping():
            pointers = self.index['data_ptrs'](0, 0x3000)
            self.assertEqual(set(pointers), {0x1000, 0x1004, 0x2000, 0x2004})
            self.assertEqual(set(self.index['data_ptrs'](0x1001, 0x2004)),
                             {0x1004, 0x2000})
            self.assertEqual(self.index['data_ptrs'](0x1008, 0x2000), {})

    def test_last_full_pointer_is_included_and_partial_pointer_is_excluded(self):
        with self.synthetic_mapping():
            self.assertEqual(set(self.index['data_ptrs'](0x2004, 0x2008)), {0x2004})
            self.assertEqual(self.index['data_ptrs'](0x2004, 0x2007), {})
            self.assertEqual(self.index['read_bytes'](0x1006, 4), b'')
            self.assertIsNone(self.index['fileoff_to_vaddr'](8))


if __name__ == '__main__':
    unittest.main()
