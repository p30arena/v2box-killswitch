import importlib.util
import json
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest
import zipfile

PATH = Path(__file__).resolve().parents[1] / 'tools/update_app_on.py'
spec = importlib.util.spec_from_file_location('on_update', PATH)
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


class OnUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.reset_fixture()

    def reset_fixture(self):
        root = Path(tempfile.mkdtemp(dir=self.tmp.name))
        self.new, self.old = root / 'new', root / 'old'
        self.new.mkdir(); self.old.mkdir()
        self.targets = {name: root / name for name in ('backend', 'app', 'pin')}
        for name, target in self.targets.items():
            if name == 'app':
                target.mkdir(); (target / 'data').write_text('old')
                (self.new / name).mkdir(); (self.new / name / 'data').write_text('new')
            else:
                target.write_text('old'); (self.new / name).write_text('new')
        self.calls = []
        self.state = {'intent': 'on', 'pf': 'enabled', 'anchor': 'approved'}
        self.expected = self.state.copy()

    def runner(self, argv):
        self.calls.append(argv)

    def apply(self, snapshot=None, runner=None):
        update.apply(self.new, self.old, self.expected, targets=self.targets,
                     snapshot=snapshot or (lambda: self.state.copy()), runner=runner or self.runner)

    def content(self, path):
        return (path / 'data').read_text() if path.is_dir() else path.read_text()

    def assert_old(self):
        self.assertTrue(all(self.content(path) == 'old' for path in self.targets.values()))

    def test_success_only_swaps_three_artifacts_and_restarts_existing_helper(self):
        self.apply()
        self.assertTrue(all(self.content(path) == 'new' for path in self.targets.values()))
        self.assertTrue(all(self.content(self.old / name) == 'old' for name in self.targets))
        self.assertEqual(self.calls, [
            ['/bin/launchctl', 'bootout', update.LABEL],
            ['/bin/launchctl', 'bootstrap', 'system', update.PLIST]])
        self.assertEqual(self.state, self.expected)

    def test_changed_protection_before_stop_does_not_stop_helper_or_move_artifacts(self):
        self.state['intent'] = 'off'
        with self.assertRaises(RuntimeError): self.apply()
        self.assertEqual(self.calls, [])
        self.assert_old()
        self.assertEqual(self.state['intent'], 'off')

    def test_snapshot_changes_at_each_later_checkpoint_restore_artifacts_not_intent(self):
        for at in range(2, 8):
            with self.subTest(checkpoint=at):
                # Recreate the local fixture for each independently interrupted run.
                self.reset_fixture()
                count = [0]
                def snapshot():
                    count[0] += 1
                    if count[0] >= at: self.state['intent'] = 'off'
                    return self.state.copy()
                with self.assertRaises(RuntimeError): self.apply(snapshot=snapshot)
                self.assert_old()
                self.assertEqual(self.state['intent'], 'off')
                self.assertFalse(any('/sbin/pfctl' in command for command in self.calls))

    def test_bootout_failure_still_attempts_restore_service(self):
        def runner(args):
            self.calls.append(args)
            if len(self.calls) == 1: raise RuntimeError('bootout outcome unknown')
        with self.assertRaises(RuntimeError): self.apply(runner=runner)
        self.assert_old()
        self.assertEqual(self.calls[-1][1], 'bootstrap')

    def test_failed_new_install_restores_artifact_already_moved_to_backup(self):
        (self.new / 'pin').unlink()
        with self.assertRaises(FileNotFoundError): self.apply()
        self.assert_old()
        self.assertEqual(self.calls[-1][1], 'bootstrap')

    def test_bootstrap_failure_rolls_back(self):
        count = [0]
        def runner(args):
            self.calls.append(args)
            if args[1] == 'bootstrap':
                count[0] += 1
                if count[0] == 1: raise RuntimeError('new start failed')
        with self.assertRaises(RuntimeError): self.apply(runner=runner)
        self.assert_old()
        self.assertEqual(count[0], 2)

    def test_keyboard_interrupt_restores_artifacts(self):
        def runner(args):
            self.calls.append(args)
            if len(self.calls) == 2: raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): self.apply(runner=runner)
        self.assert_old()

    def test_protection_reader_uses_read_only_pf_queries(self):
        base = Path(self.tmp.name)
        (base / 'state').mkdir()
        (base / 'state/intent.json').write_text(json.dumps({'version': 1, 'enabled': True}))
        calls = []
        def run(args):
            calls.append(args)
            return SimpleNamespace(stdout='Status: Enabled' if args[-1] == 'info' else 'rules')
        with patch.object(update, 'BASE', base), patch.object(update, 'digest', return_value='hash'), patch.object(update, 'run', run):
            update.protection()
        self.assertEqual(calls, [
            ['/sbin/pfctl', '-s', 'info'],
            ['/sbin/pfctl', '-a', 'com.p30arena.v2box-killswitch', '-sr'],
            ['/sbin/pfctl', '-sr']])

    def test_numeric_true_intent_does_not_pass(self):
        base = Path(self.tmp.name)
        (base / 'state').mkdir()
        (base / 'state/intent.json').write_text('{"version":1,"enabled":1}')
        with patch.object(update, 'BASE', base), patch.object(update, 'run') as run:
            with self.assertRaises(RuntimeError): update.protection()
            run.assert_not_called()

    def test_identical_filtering_modules_allow_runtime_metadata_difference(self):
        root = Path(self.tmp.name)
        left, right = root / 'old.zip', root / 'new.zip'
        for path, runtime in [(left, 'old'), (right, 'new')]:
            with zipfile.ZipFile(path, 'w') as z:
                for name in update.CORE: z.writestr(name, 'same')
                z.writestr('runtime.py', runtime)
        update.compatible(left, right)

    def test_every_filtering_module_difference_refuses(self):
        root = Path(self.tmp.name)
        left = root / 'old.zip'
        with zipfile.ZipFile(left, 'w') as z:
            for name in update.CORE: z.writestr(name, 'same')
        for changed in update.CORE:
            right = root / 'new.zip'
            with zipfile.ZipFile(right, 'w') as z:
                for name in update.CORE: z.writestr(name, 'changed' if name == changed else 'same')
            with self.assertRaises(RuntimeError): update.compatible(left, right)


if __name__ == '__main__': unittest.main()
