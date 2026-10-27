import contextlib
import io
import os
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import MagicMock, mock_open, patch


SCRIPT = Path(__file__).resolve().parents[1] / 'ovirt-auto-connect.py'


class ViewerBackendTest(unittest.TestCase):
    def run_script(self, args=(), saved=None, inherited=None, platform='linux'):
        settings = {'user': 'test', 'password': 'test', 'profile': 'test'}
        if saved is not None:
            settings['viewer-backend'] = saved
        keyring = MagicMock()
        keyring.get_password.side_effect = lambda service, key: settings.get(key)
        sdk = MagicMock()
        types = MagicMock()
        vm = MagicMock(id='vm', status=types.VmStatus.UP)
        vms = sdk.Connection.return_value.__enter__.return_value.system_service.return_value.vms_service.return_value
        vms.list.return_value = [vm]
        service = vms.vm_service.return_value
        service.get.return_value = vm
        consoles = service.graphics_consoles_service.return_value
        consoles.list.return_value = [MagicMock(id='console', protocol=types.GraphicsType.SPICE)]
        consoles.console_service.return_value.remote_viewer_connection_file.return_value = 'connection'
        env = {} if inherited is None else {'GDK_BACKEND': inherited}
        with patch.dict(sys.modules, {'keyring': keyring, 'ovirtsdk4': sdk, 'ovirtsdk4.types': types}), \
                patch.object(sys, 'argv', [str(SCRIPT), *args]), \
                patch.object(sys, 'platform', platform), \
                patch.dict(os.environ, env, clear=True), \
                patch('builtins.open', mock_open()), \
                patch('subprocess.Popen') as popen, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            # Match the object used by `import ovirtsdk4.types as types`.
            sdk.types = types
            code = 0
            try:
                runpy.run_path(str(SCRIPT), run_name='__main__')
            except SystemExit as exc:
                code = exc.code
            self.assertEqual(os.environ.get('GDK_BACKEND'), inherited)
        return code, keyring, sdk, popen

    def test_save_exits_without_connection_or_credentials_read(self):
        for backend in ('auto', 'x11', 'wayland'):
            with self.subTest(backend=backend):
                code, keyring, sdk, popen = self.run_script(['--viewer-backend', backend])
                self.assertEqual(code, 0)
                keyring.set_password.assert_called_once_with('ovirt-no-pass', 'viewer-backend', backend)
                keyring.get_password.assert_not_called()
                sdk.Connection.assert_not_called()
                popen.assert_not_called()

    def test_auto_preserves_environment(self):
        for saved in (None, 'auto'):
            for inherited in (None, 'wayland', 'x11'):
                with self.subTest(saved=saved, inherited=inherited):
                    code, _, _, popen = self.run_script(saved=saved, inherited=inherited)
                    self.assertEqual(code, 0)
                    self.assertEqual(popen.call_args.kwargs['env'].get('GDK_BACKEND'), inherited)

    def test_explicit_backend_overrides_only_child(self):
        for backend in ('x11', 'wayland'):
            with self.subTest(backend=backend):
                _, _, _, popen = self.run_script(saved=backend, inherited='other')
                self.assertEqual(popen.call_args.kwargs['env']['GDK_BACKEND'], backend)

    def test_macos_uses_aspice(self):
        _, _, _, popen = self.run_script(saved='x11', platform='darwin')
        popen.assert_called_once_with(['open', '-a', 'aSPICE', '/tmp/srw.vv'], start_new_session=True)

    def test_invalid_argument_has_no_side_effects(self):
        code, keyring, sdk, popen = self.run_script(['--viewer-backend', 'invalid'])
        self.assertEqual(code, 2)
        keyring.set_password.assert_not_called()
        sdk.Connection.assert_not_called()
        popen.assert_not_called()

    def test_invalid_saved_backend_fails_before_connection(self):
        code, _, sdk, popen = self.run_script(saved='invalid')
        self.assertEqual(code, 2)
        sdk.Connection.assert_not_called()
        popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
