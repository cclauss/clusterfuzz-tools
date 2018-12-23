"""Test the 'common' module."""
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import cStringIO
import subprocess
import os
import random
import signal
import stat

import mock
from requests import exceptions

from clusterfuzz import common
from error import error
from test_libs import helpers


class GetVersionTest(helpers.ExtendedTestCase):
  """Tests get_version."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_get_version(self):
    """Test get_version."""
    version_path = os.path.join(
        os.path.dirname(common.__file__), 'resources', 'VERSION')
    self.fs.CreateFile(version_path, contents='vvv')
    self.assertEqual('vvv', common.get_version())


class ConfirmTest(helpers.ExtendedTestCase):
  """Tests the confirm method."""

  def setUp(self):
    helpers.patch(self, ['__builtin__.raw_input'])

  def test_yes_default(self):
    """Tests functionality with yes as default."""

    self.mock.raw_input.side_effect = ['y', 'n', '']

    self.assertTrue(common.confirm('A question'))
    self.assertFalse(common.confirm('A question'))
    self.assertTrue(common.confirm('A question'))

    msg = common.emphasize(common.colorize(
        'A question [Y/n]: ', common.BASH_MAGENTA_MARKER))
    self.mock.raw_input.assert_has_calls([mock.call(msg)] * 3)
    self.assert_n_calls(3, [self.mock.raw_input])

  def test_no_default(self):
    """Tests functionality when no is the default."""

    self.mock.raw_input.side_effect = ['y', 'n', '']

    self.assertTrue(common.confirm('A question', default='n'))
    self.assertFalse(common.confirm('A question', default='n'))
    self.assertFalse(common.confirm('A question', default='n'))

    msg = common.emphasize(common.colorize(
        'A question [y/N]: ', common.BASH_MAGENTA_MARKER))
    self.mock.raw_input.assert_has_calls([mock.call(msg)] * 3)
    self.assert_n_calls(3, [self.mock.raw_input])

  def test_empty_default(self):
    """Tests functionality when default is explicitly None."""

    self.mock.raw_input.side_effect = ['y', 'n', '', 'n']

    self.assertTrue(common.confirm('A question', default=None))
    self.assertFalse(common.confirm('A question', default=None))
    self.assertFalse(common.confirm('A question', default=None))

    msg = common.emphasize(common.colorize(
        'A question [y/n]: ', common.BASH_MAGENTA_MARKER))
    another_msg = common.emphasize(common.colorize(
        'Please type either "y" or "n": ', common.BASH_MAGENTA_MARKER))
    self.mock.raw_input.assert_has_calls(
        [mock.call(msg)] * 3 + [mock.call(another_msg)])
    self.assert_n_calls(4, [self.mock.raw_input])

  def test_quiet_mode(self):
    """Tests functinality in quiet mode."""
    self.mock_os_environment({'CF_QUIET': '1'})

    self.assertTrue(common.confirm('Anything'))
    self.assertTrue(common.confirm('Anything', default='n'))

    self.assert_n_calls(0, [self.mock.raw_input])


class ExecuteTest(helpers.ExtendedTestCase):
  """Tests the execute method."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.check_binary',
        'clusterfuzz.common.kill',
        'clusterfuzz.common.wait_timeout',
        'logging.config.dictConfig',
        'logging.getLogger',
        'os.environ.copy',
        'subprocess.Popen',
        'time.sleep'
    ])
    self.mock.copy.return_value = {'OS': 'ENVIRON'}
    self.mock.dictConfig.return_value = {}

    from clusterfuzz import local_logging
    local_logging.start_loggers()
    self.stdout = 'Line 1\nLine 2\nLine 3\n'
    self.residue_stdout = 'residue'
    self.stderr = 'Err 1\nErr 2\nErr 3'

  def build_popen_mock(self, code):
    """Builds the mocked Popen object."""
    return mock.MagicMock(
        stdout=cStringIO.StringIO(self.stdout),
        stderr=cStringIO.StringIO(self.stderr),
        returncode=code)

  def run_execute(self, print_cmd, print_out, exit_on_err):
    return common.execute(
        'cmd', '',
        '~/working/directory',
        print_command=print_cmd,
        print_output=print_out,
        exit_on_error=exit_on_err,
        stdin=None,
        env={'TEST': 'VALUE'})

  def run_popen_assertions(
      self, code, print_cmd=True, print_out=True, exit_on_err=True):
    """Runs the popen command and tests the output."""
    self.mock.kill.reset_mock()
    self.mock.Popen.reset_mock()
    self.mock.Popen.return_value = self.build_popen_mock(code)
    self.mock.Popen.return_value.communicate.return_value = (
        self.residue_stdout, self.stderr)
    self.mock.Popen.return_value.args = 'cmd'
    will_exit = exit_on_err and code != 0

    if will_exit:
      with self.assertRaises(error.CommandFailedError) as cm:
        self.run_execute(print_cmd, print_out, exit_on_err)

      self.assertEqual(
          error.CommandFailedError.MESSAGE.format(
              cmd='cmd', returncode='1', stderr=self.stderr),
          cm.exception.message)
    else:
      return_code, returned_lines = self.run_execute(
          print_cmd, print_out, exit_on_err)
      self.assertEqual(return_code, code)
      self.assertEqual(
          returned_lines, self.stdout + self.residue_stdout + self.stderr)

    self.mock.kill.assert_called_once_with(self.mock.Popen.return_value)
    self.mock.Popen.return_value.communicate.assert_called_once_with()
    self.mock.Popen.assert_called_once_with(
        'cmd',
        shell=True,
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd='~/working/directory',
        env=dict({'OS': 'ENVIRON', 'TEST': 'VALUE'}, **common.BLACKLISTED_ENVS),
        preexec_fn=os.setsid)

  def test_process_runs_successfully(self):
    """Test execute when the process successfully runs."""

    return_code = 0
    for print_cmd in [True, False]:
      for print_out in [True, False]:
        for exit_on_error in [True, False]:
          self.run_popen_assertions(
              return_code, print_cmd, print_out, exit_on_error)

  def test_process_run_fails(self):
    """Test execute when the process does not run successfully."""

    return_code = 1
    for print_cmd in [True, False]:
      for print_out in [True, False]:
        for exit_on_error in [True, False]:
          self.run_popen_assertions(
              return_code, print_cmd, print_out, exit_on_error)

  def test_check_binary_fail(self):
    """Test check_binary fail."""
    self.mock.check_binary.side_effect = error.NotInstalledError('cmd')

    with self.assertRaises(error.NotInstalledError) as cm:
      common.execute('cmd', 'aaa', '~/working/directory')

    self.assert_exact_calls(
        self.mock.check_binary, [mock.call('cmd', '~/working/directory')])
    self.assertEqual(
        error.NotInstalledError.MESSAGE.format(binary='cmd'),
        cm.exception.message)


class CheckBinaryTest(helpers.ExtendedTestCase):
  """Test check_binary."""

  def setUp(self):
    helpers.patch(self, ['subprocess.check_output'])

  def test_valid(self):
    """Test a valid binary."""
    common.check_binary('test', 'cwd')
    self.mock.check_output.assert_called_once_with(['which', 'test'], cwd='cwd')

  def test_invalid(self):
    """Test an invalid binary."""
    self.mock.check_output.side_effect = subprocess.CalledProcessError(1, '')
    with self.assertRaises(error.NotInstalledError) as cm:
      common.check_binary('test', 'cwd')

    self.mock.check_output.assert_called_once_with(['which', 'test'], cwd='cwd')
    self.assertEqual(
        error.NotInstalledError.MESSAGE.format(binary='test'),
        cm.exception.message)


class StoreAuthHeaderTest(helpers.ExtendedTestCase):
  """Tests the store_auth_header method."""

  def setUp(self):
    self.setup_fake_filesystem()
    self.auth_header = 'Bearer 12345'

  def test_folder_absent(self):
    """Tests storing when the folder has not been created prior."""

    self.assertFalse(os.path.exists(common.CLUSTERFUZZ_CACHE_DIR))
    common.store_auth_header(self.auth_header)

    self.assertTrue(os.path.exists(common.CLUSTERFUZZ_CACHE_DIR))
    with open(common.AUTH_HEADER_FILE, 'r') as f:
      self.assertEqual(f.read(), self.auth_header)
    self.assert_file_permissions(common.AUTH_HEADER_FILE, 600)

  def test_folder_present(self):
    """Tests storing when the folder has already been created."""

    self.fs.CreateFile(common.AUTH_HEADER_FILE)
    common.store_auth_header(self.auth_header)

    with open(common.AUTH_HEADER_FILE, 'r') as f:
      self.assertEqual(f.read(), self.auth_header)
    self.assert_file_permissions(common.AUTH_HEADER_FILE, 600)


class GetStoredAuthHeaderTest(helpers.ExtendedTestCase):
  """Tests the stored_auth_key method."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_file_missing(self):
    """Tests functionality when auth key file does not exist."""

    result = common.get_stored_auth_header()
    self.assertEqual(result, None)

  def test_permissions_incorrect(self):
    """Tests functionality when file exists but permissions wrong."""

    self.fs.CreateFile(common.AUTH_HEADER_FILE)
    os.chmod(common.AUTH_HEADER_FILE, stat.S_IWGRP)

    with self.assertRaises(error.PermissionsTooPermissiveError) as ex:
      result = common.get_stored_auth_header()
      self.assertEqual(result, None)
    self.assertIn(
        'File permissions too permissive to open',
        ex.exception.message)

  def test_file_valid(self):
    """Tests when file is accessible and auth key is returned."""

    self.fs.CreateFile(common.AUTH_HEADER_FILE, contents='Bearer 1234')
    os.chmod(common.AUTH_HEADER_FILE, stat.S_IWUSR|stat.S_IRUSR)

    result = common.get_stored_auth_header()
    self.assertEqual(result, 'Bearer 1234')


class CheckConfirmTest(helpers.ExtendedTestCase):
  """Tests the check_confirm method."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.confirm'])

  def test_answer_yes(self):
    self.mock.confirm.return_value = True
    common.check_confirm('Question?')
    self.assert_exact_calls(self.mock.confirm, [mock.call('Question?')])

  def test_answer_no(self):
    self.mock.confirm.return_value = False
    with self.assertRaises(error.UserRespondingNoError):
      common.check_confirm('Question?')
    self.assert_exact_calls(self.mock.confirm, [mock.call('Question?')])


class AskTest(helpers.ExtendedTestCase):
  """Tests the ask method."""

  def setUp(self):
    helpers.patch(self, ['__builtin__.raw_input'])
    self.mock.raw_input.side_effect = [
        'wrong', 'still wrong', 'very wrong', 'correct']

  def test_returns_when_correct(self):
    """Tests that the method only returns when the answer fits validation."""

    question = 'Initial Question'
    error_message = 'Please answer correctly'
    validate_fn = lambda x: x == 'correct'

    result = common.ask(question, error_message, validate_fn)
    self.assert_n_calls(4, [self.mock.raw_input])
    self.mock.raw_input.assert_has_calls([
        mock.call(common.emphasize(common.colorize(
            'Initial Question: ', common.BASH_MAGENTA_MARKER))),
        mock.call(common.emphasize(common.colorize(
            'Please answer correctly: ', common.BASH_MAGENTA_MARKER)))
    ])
    self.assertEqual(result, 'correct')


class DefinitionTest(helpers.ExtendedTestCase):
  """Tests the Definition class."""

  def test_no_sanitizer(self):
    with self.assertRaises(error.SanitizerNotProvidedError):
      common.Definition(
          builder='builder', source_name='chromium', reproducer='reproducer',
          binary_name=None, sanitizer=None, targets=None,
          require_user_data_dir=False, revision_url=None)


class WaitTimeoutTest(helpers.ExtendedTestCase):
  """Tests the wait_timeout method."""

  def setUp(self):
    helpers.patch(self, ['time.sleep', 'clusterfuzz.common.kill'])
    self.proc = mock.Mock()

  def test_no_timeout(self):
    """Test no timeout."""
    common.wait_timeout(self.proc, None)
    self.assertEqual(0, self.mock.sleep.call_count)
    self.assertEqual(0, self.proc.poll.call_count)

  def test_die_before(self):
    """Tests when the process exits without needing to be killed."""
    self.proc.poll.side_effect = [None, None, None, 1]

    common.wait_timeout(self.proc, 5)

    self.mock.kill.assert_called_once_with(self.proc)
    self.assert_exact_calls(self.mock.sleep, [mock.call(0.5)] * 4)

  def test_timeout(self):
    """Tests when the process must be killed."""
    self.proc.poll.return_value = None

    common.wait_timeout(self.proc, 5)

    self.mock.kill.assert_called_once_with(self.proc)
    self.assert_exact_calls(
        self.mock.sleep, [mock.call(0.5)] * 10)

  def test_ignore_kill_error(self):
    """Tests ignoring error from killing."""
    self.mock.kill.side_effect = Exception()
    common.wait_timeout(self.proc, 5)
    self.mock.kill.assert_called_once_with(self.proc)


class KillTest(helpers.ExtendedTestCase):
  """Test kill method."""

  def setUp(self):
    helpers.patch(self, ['time.sleep', 'os.killpg'])
    self.proc = mock.Mock()
    self.proc.args = 'cmd'
    self.proc.pid = 1234

    self.no_process_error = OSError()
    self.no_process_error.errno = common.NO_SUCH_PROCESS_ERRNO

  def test_succeed(self):
    """Test killing successfully."""
    self.mock.killpg.side_effect = [None, None, None, self.no_process_error]
    common.kill(self.proc)

    self.assert_exact_calls(self.mock.killpg, [
        mock.call(1234, signal.SIGTERM), mock.call(1234, signal.SIGTERM),
        mock.call(1234, signal.SIGKILL), mock.call(1234, signal.SIGKILL)
    ])
    self.assert_exact_calls(self.mock.sleep, [mock.call(3)] * 3)

  def test_fail(self):
    """Test failing to kill."""
    self.mock.killpg.side_effect = [None, None, None, None]

    with self.assertRaises(error.KillProcessFailedError) as cm:
      common.kill(self.proc)

    self.assertEqual(
        '`cmd` (pid=1234) cannot be killed.',
        cm.exception.message)

    self.assert_exact_calls(self.mock.killpg, [
        mock.call(1234, signal.SIGTERM), mock.call(1234, signal.SIGTERM),
        mock.call(1234, signal.SIGKILL), mock.call(1234, signal.SIGKILL)
    ])
    self.assert_exact_calls(self.mock.sleep, [mock.call(3)] * 4)

  def test_other_error(self):
    """Test raising other OSError."""
    err = OSError()
    err.errno = 4
    self.mock.killpg.side_effect = err

    with self.assertRaises(OSError) as cm:
      common.kill(self.proc)

    self.assertEqual(4, cm.exception.errno)


class DeleteIfExistsTest(helpers.ExtendedTestCase):
  """Tests the delete_if_exists method."""

  def setUp(self):
    self.setup_fake_filesystem()
    self.directory = '/testcase'
    self.filename = os.path.join(self.directory, 'testcase.js')
    os.makedirs(self.directory)
    self.fs.CreateFile(self.filename, contents='text')

  def test_delete_dir(self):
    """Ensure the dir is deleted."""
    common.delete_if_exists(self.directory)
    self.assertFalse(os.path.exists(self.directory))
    self.assertFalse(os.path.exists(self.filename))

  def test_delete_file(self):
    """Ensure the file is deleted."""
    common.delete_if_exists(self.filename)
    self.assertTrue(os.path.exists(self.directory))
    self.assertFalse(os.path.exists(self.filename))


class EnsureDirTest(helpers.ExtendedTestCase):
  """Tests the ensure_dir method."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_not_exist(self):
    """Test ensuring dir when the dir doesn't exist."""
    self.assertFalse(os.path.exists('/test'))
    common.ensure_dir('/test')
    self.assertTrue(os.path.exists('/test'))

  def test_exist(self):
    """Test ensuring dir when the dir exists."""
    os.makedirs('/test')
    self.assertTrue(os.path.exists('/test'))
    common.ensure_dir('/test')
    self.assertTrue(os.path.exists('/test'))


class GetValidAbsDirTest(helpers.ExtendedTestCase):
  """Tests for get_valid_abs_dir."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_validity(self):
    """Test a valid dir."""
    os.makedirs('/test/test2')
    self.assertEqual('/test/test2', common.get_valid_abs_dir('/test/test2'))
    self.assertIsNone(common.get_valid_abs_dir('/test/test3'))

  def test_empty(self):
    """Test empty."""
    self.assertIsNone(common.get_valid_abs_dir(''))


class StyleTest(helpers.ExtendedTestCase):
  """Test colorize."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.get_os_name'])

  def test_posix(self):
    """Test posix."""
    self.mock.get_os_name.return_value = 'posix'
    self.assertEqual(
        common.BASH_BLUE_MARKER + 'test' + common.BASH_RESET_COLOR_MARKER,
        common.style(
            'test', common.BASH_BLUE_MARKER, common.BASH_RESET_COLOR_MARKER)
    )

  def test_not_posix(self):
    """Test not posix."""
    self.mock.get_os_name.return_value = 'windows'
    self.assertEqual(
        'test',
        common.style(
            'test', common.BASH_BLUE_MARKER, common.BASH_RESET_COLOR_MARKER)
    )


class ColorizeTest(helpers.ExtendedTestCase):
  """Test colorize."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.style'])
    self.mock.style.return_value = 'style'

  def test_colorize(self):
    """Test colorize."""
    self.assertEqual('style', common.colorize('s', common.BASH_BLUE_MARKER))
    self.mock.style.assert_called_once_with(
        's', common.BASH_BLUE_MARKER, common.BASH_RESET_COLOR_MARKER)


class EmphasizeTest(helpers.ExtendedTestCase):
  """Test colorize."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.style'])
    self.mock.style.return_value = 'style'

  def test_emphasize(self):
    """Test emphasize."""
    self.assertEqual('style', common.emphasize('s'))
    self.mock.style.assert_called_once_with(
        's', common.BASH_BOLD_MARKER, common.BASH_RESET_STYLE_MARKER)


class GsutilTest(helpers.ExtendedTestCase):
  """Tests gsutil."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_succeed(self):
    """Test suceeding."""
    self.mock.execute.return_value = (0, None)
    self.assertEqual((0, None), common.gsutil('test', cwd='source'))

    self.mock.execute.assert_called_once_with('gsutil', 'test', cwd='source')

  def test_fail(self):
    """Test failing with NotInstalledError."""
    self.mock.execute.side_effect = error.NotInstalledError('gsutil')
    with self.assertRaises(error.GsutilNotInstalledError):
      common.gsutil('test', cwd='source')

    self.mock.execute.assert_called_once_with('gsutil', 'test', cwd='source')

  def test_fail_other(self):
    """Test failing with other exception."""
    self.mock.execute.side_effect = subprocess.CalledProcessError(1, 'cmd', 'o')
    with self.assertRaises(subprocess.CalledProcessError) as cm:
      common.gsutil('test', cwd='source')

    self.assertEqual(self.mock.execute.side_effect, cm.exception)
    self.mock.execute.assert_called_once_with('gsutil', 'test', cwd='source')


class StringStdinTest(helpers.ExtendedTestCase):
  """Tests StringStdin."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_stdin(self):
    """Test input is a string."""
    stdin = common.StringStdin('some input')

    with open(stdin.stdin.name) as f:
      self.assertEqual('some input', f.read())
    self.assertEqual('some input', stdin.get().read())
    self.assertEqual('cmd < %s' % stdin.stdin.name, stdin.update_cmd_log('cmd'))


class UserStdinTest(helpers.ExtendedTestCase):
  """Tests UserStdin."""

  def test_stdin(self):
    """Test stdin."""
    stdin = common.UserStdin()
    self.assertIsNone(stdin.get())
    self.assertEqual('cmd', stdin.update_cmd_log('cmd'))


class BlockStdinTest(helpers.ExtendedTestCase):
  """Tests BlockStdin."""

  def test_stdin(self):
    """Test stdin."""
    stdin = common.BlockStdin()
    self.assertEqual(subprocess.PIPE, stdin.get())
    self.assertEqual('cmd', stdin.update_cmd_log('cmd'))


class EditIfNeededTest(helpers.ExtendedTestCase):
  """Tests edit_if_needed."""

  def setUp(self):
    helpers.patch(self, ['cmd_editor.editor.edit'])

  def test_not_edit(self):
    """Test when we shouldn't edit it."""
    self.assertEqual(
        'test', common.edit_if_needed('test', 'p', 'c', False))
    self.assertEqual(0, self.mock.edit.call_count)

  def test_edit(self):
    """Test editing."""
    self.mock.edit.return_value = 'test2'
    self.assertEqual(
        'test2', common.edit_if_needed('test', 'p', 'c', True))

    self.mock.edit.assert_called_once_with('test', prefix='p', comment='c')


class DummyMemoize(object):
  """Dummy class for testing memoize."""

  def __init__(self, a, b):
    self.a_value = a
    self.b_value = b

    self.a_execution_count = 0
    self.b_execution_count = 0

  @common.memoize
  def a(self):
    self.a_execution_count += 1
    return self.a_value

  @common.memoize
  def b(self, arg):
    self.b_execution_count += 1
    return self.b_value + arg


@common.memoize
def dummy_memoize():
  return random.randint(1, 1000000)


class MemoizeTest(helpers.ExtendedTestCase):
  """Test memoize."""

  def test_memoize_module(self):
    """Test memoizing a module function."""
    result = dummy_memoize()
    for _ in range(10):
      self.assertEqual(result, dummy_memoize())

  def test_different_args(self):
    """Test memoizing different arguments."""
    dummy = DummyMemoize('a', 'b')

    for _ in range(10):
      self.assertEqual('ba', dummy.b('a'))
    self.assertEqual(1, dummy.b_execution_count)

    for _ in range(10):
      self.assertEqual('baaa', dummy.b('aaa'))
    self.assertEqual(2, dummy.b_execution_count)

  def test_different_instances(self):
    """Test memoizing different instances."""
    dummy_0 = DummyMemoize('a', 'b')
    dummy_1 = DummyMemoize('c', 'd')

    for _ in range(5):
      self.assertEqual('a', dummy_0.a())
      self.assertEqual('bx', dummy_0.b('x'))
      self.assertEqual('c', dummy_1.a())
      self.assertEqual('dx', dummy_1.b('x'))

    self.assertEqual(1, dummy_0.a_execution_count)
    self.assertEqual(1, dummy_0.b_execution_count)
    self.assertEqual(1, dummy_1.a_execution_count)
    self.assertEqual(1, dummy_1.b_execution_count)


class PostTest(helpers.ExtendedTestCase):
  """Test post."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, [
        'requests_cache.CachedSession',
        'time.sleep'
    ])
    self.http = mock.Mock()
    self.mock.CachedSession.return_value = self.http

  def test_post(self):
    """Test post."""
    self.http.post.return_value = 'returned'
    self.assertEqual(
        'returned',
        common.post(
            url='a', headers={'c': 'd'}, data={'e': 'f'}, random='thing'))

    self.assertTrue(os.path.exists(common.CLUSTERFUZZ_TESTCASES_DIR))
    self.assertEqual(1, self.mock.CachedSession.call_count)
    self.assertEqual(1, self.http.mount.call_count)
    self.http.post.assert_called_once_with(
        url='a', headers={'c': 'd'}, data={'e': 'f'}, random='thing')

  def test_retry(self):
    """Test retrying."""
    self.http.post.side_effect = (
        [exceptions.ConnectionError()] * common.RETRY_COUNT +
        ['Something'])

    self.assertEqual(
        'Something',
        common.post(
            url='a', headers={'c': 'd'}, data={'e': 'f'}, random='thing'))

    self.assertTrue(os.path.exists(common.CLUSTERFUZZ_TESTCASES_DIR))
    self.assertEqual(common.RETRY_COUNT + 1, self.mock.CachedSession.call_count)
    self.assertEqual(common.RETRY_COUNT + 1, self.http.mount.call_count)
    self.assert_exact_calls(
        self.http.post,
        [
            mock.call(
                url='a', headers={'c': 'd'}, data={'e': 'f'}, random='thing')
        ] * (common.RETRY_COUNT + 1)
    )

  def test_exception(self):
    """Test retrying."""
    self.http.post.side_effect = (
        [exceptions.ConnectionError()] * (common.RETRY_COUNT + 1))

    with self.assertRaises(exceptions.ConnectionError):
      common.post(
          url='a', headers={'c': 'd'}, data={'e': 'f'}, random='thing')

    self.assertTrue(os.path.exists(common.CLUSTERFUZZ_TESTCASES_DIR))
    self.assertEqual(common.RETRY_COUNT + 1, self.mock.CachedSession.call_count)
    self.assertEqual(common.RETRY_COUNT + 1, self.http.mount.call_count)
    self.assert_exact_calls(
        self.http.post,
        [
            mock.call(
                url='a', headers={'c': 'd'}, data={'e': 'f'}, random='thing')
        ] * (common.RETRY_COUNT + 1)
    )


class EnsureImportantDirsTest(helpers.ExtendedTestCase):
  """Tests ensure_important_dirs."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.ensure_dir',
        'clusterfuzz.common.delete_if_exists'
    ])

  def test_ensure(self):
    """Tests ensure."""
    common.ensure_important_dirs()
    self.assert_exact_calls(self.mock.ensure_dir, [
        mock.call(path) for path in common.IMPORTANT_DIRS
    ])
    self.assert_exact_calls(self.mock.delete_if_exists, [
        mock.call(common.CLUSTERFUZZ_TMP_DIR)
    ])


class FindFileTest(helpers.ExtendedTestCase):
  """Tests find_file."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_not_found(self):
    """Tests not found."""
    os.makedirs('/tmp/test/sub')
    self.fs.CreateFile('/tmp/test/sub/test.hello', contents='test')

    with self.assertRaises(Exception):
      common.find_file('args.gn', '/tmp/test')

  def test_find(self):
    """Tests not found."""
    os.makedirs('/tmp/test/sub')
    self.fs.CreateFile('/tmp/test/sub/test.hello', contents='test')
    self.fs.CreateFile('/tmp/test/sub/args.gn', contents='test')

    self.assertEqual(
        '/tmp/test/sub/args.gn',
        common.find_file('args.gn', '/tmp/test'))
