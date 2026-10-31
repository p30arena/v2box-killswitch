import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

PATH = Path(__file__).resolve().parents[1] / 'tools/remove_approval_expiry_on.py'
spec = importlib.util.spec_from_file_location('remove_expiry', PATH)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)


class RemoveExpiryTests(unittest.TestCase):
    def test_only_active_expiry_changes(self):
        before = {'profile': 'one', 'service_uuid': 'fixed', 'inventory': {'profiles': {
            'one': {'expires_at': 123, 'revision': '7', 'endpoints': ['fixed-peer']},
            'two': {'expires_at': 456, 'revision': '8', 'endpoints': ['other-peer']}}}}
        result = json.loads(mod.permanent_config(json.dumps(before).encode()))
        self.assertIsNone(result['inventory']['profiles']['one']['expires_at'])
        result['inventory']['profiles']['one']['expires_at'] = 123
        self.assertEqual(result, before)

    def test_no_silent_reapproval_of_already_permanent_record(self):
        raw = b'{"profile":"one","inventory":{"profiles":{"one":{"expires_at":null}}}}'
        with self.assertRaises(RuntimeError): mod.permanent_config(raw)

    def test_zip_patch_preserves_entrypoint_and_all_other_modules(self):
        prefix = b'#!/usr/bin/python3 -I\n'; output = io.BytesIO(); output.write(prefix)
        old, new = b'old module', b'new module with different compressed length' * 10
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('__main__.py', 'fixed entrypoint')
            z.writestr('endpoints.py', old)
            z.writestr('policy.py', 'must remain identical')
        original = output.getvalue()
        with patch.object(mod, 'OLD_HASH', mod.sha(old)), patch.object(mod, 'NEW_HASH', mod.sha(new)):
            result = mod.rewrite_backend(original, new)
            self.assertTrue(result.startswith(prefix))
            with zipfile.ZipFile(io.BytesIO(result)) as z:
                self.assertEqual(z.read('endpoints.py'), new)
                self.assertEqual(z.read('policy.py'), b'must remain identical')
                self.assertEqual(z.read('__main__.py'), b'fixed entrypoint')
            with self.assertRaises(RuntimeError): mod.rewrite_backend(original, b'wrong replacement')
            with self.assertRaises(RuntimeError): mod.rewrite_backend(result, new)

    def test_unrecognized_zipapp_refused(self):
        with self.assertRaises(RuntimeError): mod.rewrite_backend(b'not a zipapp', b'not reviewed')

    def test_status_read_retry_is_bounded_and_does_not_retry_validation_failures(self):
        from subprocess import CalledProcessError
        from unittest.mock import Mock
        reader = Mock(side_effect=[CalledProcessError(1, ['fixed-status']), None])
        with patch.object(mod.time, 'sleep'):
            mod.checked_status({'status': reader})
        self.assertEqual(reader.call_count, 2)
        reader = Mock(side_effect=CalledProcessError(1, ['fixed-status']))
        with patch.object(mod.time, 'sleep'), self.assertRaises(CalledProcessError):
            mod.checked_status({'status': reader})
        self.assertEqual(reader.call_count, 4)
        reader = Mock(side_effect=RuntimeError('not On'))
        with self.assertRaises(RuntimeError): mod.checked_status({'status': reader})
        self.assertEqual(reader.call_count, 1)

    def test_atomic_write_retains_explicit_permissions_and_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'approval'
            mod.atomic(path, b'old', 0o600); mod.atomic(path, b'new', 0o600)
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])


if __name__ == '__main__': unittest.main()
