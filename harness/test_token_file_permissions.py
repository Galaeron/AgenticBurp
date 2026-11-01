"""R14 disposable credential publication; never reads/writes a live token."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from harness import security
from harness.test_pairing_contract import PairingCallerTests


def acl(path):
    script = r"""
    $ErrorActionPreference='Stop'
    $a = [System.IO.File]::GetAccessControl($env:AGENTIC_ACL_TEST_PATH)
    $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $rules=@($a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
        @{sid=$_.IdentityReference.Value; type=$_.AccessControlType.ToString(); inherited=$_.IsInherited; rights=$_.FileSystemRights.ToString()}
    })
    @{protected=$a.AreAccessRulesProtected; current_sid=$sid; owner=$a.Owner; rules=$rules} | ConvertTo-Json -Depth 4 -Compress
    """
    environment=os.environ.copy()
    environment.pop('PSModulePath',None)
    environment['AGENTIC_ACL_TEST_PATH']=str(path)
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
                          env=environment,capture_output=True,text=True,check=True,timeout=15,
                          creationflags=subprocess.CREATE_NO_WINDOW)
    return json.loads(result.stdout)


class TokenFilePermissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path=Path(self.temporary.name)/'synthetic-token.lock'

    def test_actual_publication_is_private_before_and_after_replacement(self):
        for value in ('synthetic-r14-first','synthetic-r14-second'):
            security.write_private_credential_file(self.path,value)
            self.assertEqual(self.path.read_text(),value)
            if os.name == 'nt':
                actual=acl(self.path)
                self.assertTrue(actual['protected'])
                self.assertEqual(len(actual['rules']),1)
                self.assertEqual(actual['rules'][0]['sid'],actual['current_sid'])
                self.assertEqual(actual['rules'][0]['type'],'Allow')
                self.assertFalse(actual['rules'][0]['inherited'])
            else:
                self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        self.assertEqual(list(self.path.parent.glob('.credential-*')),[])

    @unittest.skipUnless(os.name == 'nt','Windows DACL control')
    def test_acl_failure_publishes_no_bytes_and_preserves_existing_disposable_file(self):
        self.path.write_text('synthetic-existing')
        def fail(empty):
            self.assertEqual(empty.read_bytes(),b'')
            raise PermissionError('synthetic ACL failure')
        with patch('harness.security._restrict_windows_file_acl',side_effect=fail):
            with self.assertRaises(PermissionError):
                security.write_private_credential_file(self.path,'synthetic-secret-never-published')
        self.assertEqual(self.path.read_text(),'synthetic-existing')
        self.assertEqual(list(self.path.parent.glob('.credential-*')),[])

    @unittest.skipUnless(os.name == 'nt','Windows DACL control')
    def test_defect_control_missing_protection_leaves_inherited_acl(self):
        with patch('harness.security._restrict_windows_file_acl',return_value=None):
            security.write_private_credential_file(self.path,'synthetic-defect-only')
        self.assertFalse(acl(self.path)['protected'])


class TokenPublicationCallerTests(PairingCallerTests):
    def test_actual_server_publication_uses_private_policy(self):
        path=Path(self.tmp.name)/'synthetic-server-token.lock'
        with patch.object(self.server,'TOKEN_LOCKFILE_PATH',path):
            self.assertTrue(self.server._write_token_lockfile('synthetic-server-token'))
        self.assertEqual(path.read_text(),'synthetic-server-token')
        if os.name == 'nt':
            self.assertTrue(acl(path)['protected'])

    def test_server_acl_failure_reports_stale_file_without_secret(self):
        path=Path(self.tmp.name)/'synthetic-server-token.lock'
        path.write_text('synthetic-existing')
        with patch.object(self.server,'TOKEN_LOCKFILE_PATH',path), patch(
                'harness.security.write_private_credential_file',side_effect=PermissionError('synthetic-secret')):
            with self.assertLogs(self.server.log,'WARNING') as logs:
                self.assertFalse(self.server._write_token_lockfile('synthetic-secret'))
        self.assertEqual(path.read_text(),'synthetic-existing')
        self.assertIn('prior lockfile may be stale',''.join(logs.output))
        self.assertNotIn('synthetic-secret',''.join(logs.output))
