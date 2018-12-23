"""Tests the main module of the CI service."""
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

import os
import tempfile
import yaml

import mock

from daemon import main
from error import error
from test_libs import helpers


class MainTest(helpers.ExtendedTestCase):
  """Test main."""

  def setUp(self):
    helpers.patch(self, [
        'daemon.main.load_sanity_check_testcase_ids',
        'daemon.main.reset_and_run_testcase',
        'daemon.main.update_auth_header',
        'daemon.main.load_new_testcases',
        'daemon.main.prepare_binary_and_get_version',
        'time.sleep'
    ])
    self.mock_os_environment({'RELEASE': 'release-test'})
    self.setup_fake_filesystem()
    self.mock.load_sanity_check_testcase_ids.return_value = [1, 2]
    self.mock.load_new_testcases.side_effect = [
        [main.Testcase(3, 'job'), main.Testcase(4, 'job')],
        [main.Testcase(5, 'job')],
        []
    ]

  def test_correct_calls(self):
    """Ensure the main method makes the correct calls to reproduce."""
    main.main()

    self.assert_exact_calls(
        self.mock.load_sanity_check_testcase_ids, [mock.call()])
    self.assert_exact_calls(
        self.mock.load_new_testcases, [mock.call()] * 3)
    self.assert_exact_calls(self.mock.reset_and_run_testcase, [
        mock.call(1, 'sanity', 'release-test'),
        mock.call(2, 'sanity', 'release-test'),
        mock.call(3, 'job', 'release-test'),
        mock.call(4, 'job', 'release-test'),
        mock.call(5, 'job', 'release-test')])
    self.assertEqual(3, self.mock.update_auth_header.call_count)
    self.mock.prepare_binary_and_get_version.assert_called_once_with(
        'release-test')


class RunTestcaseTest(helpers.ExtendedTestCase):
  """Test the run_testcase method."""

  def setUp(self):
    helpers.patch(self, ['daemon.process.call'])
    self.mock_os_environment({'PATH': 'test'})
    main.PROCESSED_TESTCASE_IDS.clear()

  def test_succeed(self):
    """Ensures testcases are run properly."""
    self.mock.call.return_value = (0, None)
    self.assertEqual(0, main.run_testcase(1234, '--current'))

    self.assert_exact_calls(self.mock.call, [
        mock.call(
            '/python-daemon-data/clusterfuzz reproduce 1234 --current',
            cwd=main.HOME,
            env={
                'CF_QUIET': '1',
                'CHROMIUM_SRC': main.CHROMIUM_SRC,
                'PATH': 'test:%s' % main.DEPOT_TOOLS,
                'GOMA_GCE_SERVICE_ACCOUNT': 'default'},
            raise_on_error=False,
            timeout=main.REPRODUCE_TOOL_TIMEOUT)
    ])
    self.assertIn(1234, main.PROCESSED_TESTCASE_IDS)


class LoadSanityCheckTestcasesTest(helpers.ExtendedTestCase):
  """Tests the load_sanity_check_testcases method."""

  def setUp(self):
    self.setup_fake_filesystem()
    os.makedirs(os.path.dirname(main.SANITY_CHECKS))
    with open(main.SANITY_CHECKS, 'w') as f:
      f.write('testcase_ids:\n')
      f.write('#ignore\n')
      f.write('        - 5899279404367872')

  def test_reading_testcases(self):
    """Ensures that testcases are read properly."""

    result = main.load_sanity_check_testcase_ids()
    self.assertEqual(result, [5899279404367872])


class UpdateAuthHeadertest(helpers.ExtendedTestCase):
  """Tests the update_auth_header method."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, ['oauth2client.client.GoogleCredentials'])
    (self.mock.GoogleCredentials._get_implicit_credentials.return_value. #pylint: disable=protected-access
     get_access_token.return_value) = mock.Mock(access_token='Access token')

  def test_proper_update(self):
    """Ensures that the auth key is updated properly."""

    self.assertFalse(os.path.exists(main.CLUSTERFUZZ_CACHE_DIR))
    main.update_auth_header()

    with open(main.AUTH_FILE_LOCATION, 'r') as f:
      self.assertEqual(f.read(), 'Bearer Access token')


class GetBinaryVersionTest(helpers.ExtendedTestCase):
  """Tests the get_binary_version method."""

  def setUp(self):
    helpers.patch(self, ['daemon.process.call'])
    self.result = yaml.dump({
        'chromium': ['chrome_job', 'libfuzzer_job'],
        'standalone': ['pdf_job', 'v8_job'],
        'Version': '0.2.2rc11'})
    self.mock.call.return_value = (0, self.result)

  def test_get(self):
    result = main.get_binary_version()
    self.assertEqual(result, '0.2.2rc11')


class GetSupportedJobtypesTest(helpers.ExtendedTestCase):
  """Tests the get_supported_jobtypes method."""

  def setUp(self):
    helpers.patch(self, ['daemon.process.call'])
    self.result = yaml.dump({
        'chromium': ['chrome_job', 'libfuzzer_job'],
        'standalone': ['pdf_job', 'v8_job'],
        'Version': '0.2.2rc11'})
    self.mock.call.return_value = (0, self.result)

  def test_get_supported_jobtypes(self):
    """Tests get_supported_jobtypes."""

    result = main.get_supported_jobtypes()
    correct = yaml.load(self.result)
    correct.pop('Version')
    self.assertEqual(result, correct)


class LoadNewTestcasesTest(helpers.ExtendedTestCase):
  """Tests the load_new_testcases method."""

  def setUp(self):
    self.setup_fake_filesystem()
    os.makedirs(main.CLUSTERFUZZ_CACHE_DIR)
    with open(main.AUTH_FILE_LOCATION, 'w') as f:
      f.write('Bearer xyzabc')

    helpers.patch(self, [
        'daemon.main.get_supported_jobtypes',
        'daemon.main.post',
        'daemon.main.is_time_valid',
        'random.randint',
        'time.time',
        'time.sleep'
    ])
    main.PROCESSED_TESTCASE_IDS.clear()

  def test_get_testcase(self):
    """Tests get testcase."""
    self.mock.is_time_valid.side_effect = lambda t: t != 2
    self.mock.randint.return_value = 6
    self.mock.get_supported_jobtypes.return_value = {'chromium': [
        'supported0', 'supported1']}
    resp = mock.Mock()
    resp.json.side_effect = (
        [{
            'items': [
                {'jobType': 'supported0', 'id': 12345, 'timestamp': 1},
                {'jobType': 'supported0', 'id': 555, 'timestamp': 2.2},
                {'jobType': 'unsupported', 'id': 98765, 'timestamp': 3},
                {'jobType': 'supported1', 'id': 23456, 'timestamp': 4},
                {'jobType': 'supported0', 'id': 23456, 'timestamp': 5},
                {'jobType': 'supported0', 'id': 1337, 'timestamp': 6},
            ]
        }] * 15
        + [{'items': []}]
    )
    self.mock.post.return_value = resp
    main.PROCESSED_TESTCASE_IDS[1337] = True

    result = main.load_new_testcases()

    self.assertEqual(
        [main.Testcase(12345, 'supported0'),
         main.Testcase(23456, 'supported1')],
        result)
    self.assert_exact_calls(self.mock.post, [
        mock.call(
            'https://clusterfuzz.com/testcases/load',
            headers={'Authorization': 'Bearer xyzabc'},
            json={'page': page, 'reproducible': 'yes',
                  'q': 'platform:linux', 'open': 'yes',
                  'project': 'chromium'})
        for page in range(1, 17)
    ])


class ResetAndRunTestcaseTest(helpers.ExtendedTestCase):
  """Tests the reset_and_run_testcase method."""

  def setUp(self):
    self.setup_fake_filesystem()
    os.makedirs(main.CHROMIUM_OUT)
    os.makedirs(main.CLUSTERFUZZ_CACHE_DIR)

    helpers.patch(self, [
        'daemon.stackdriver_logging.send_run',
        'daemon.main.update_auth_header',
        'daemon.main.run_testcase',
        'daemon.main.prepare_binary_and_get_version',
        'daemon.main.read_logs',
        'daemon.main.clean',
        'daemon.main.sleep',
    ])
    self.mock.prepare_binary_and_get_version.return_value = '0.2.2rc10'
    self.mock.run_testcase.return_value = 'run_testcase'
    self.mock.read_logs.return_value = 'some logs'

  def test_reset_run_testcase(self):
    """Tests resetting a testcase properly prior to running."""

    self.assertTrue(os.path.exists(main.CHROMIUM_OUT))
    self.assertTrue(os.path.exists(main.CLUSTERFUZZ_CACHE_DIR))
    main.reset_and_run_testcase(1234, 'sanity', 'master')
    self.assertFalse(os.path.exists(main.CHROMIUM_OUT))
    self.assertFalse(os.path.exists(main.CLUSTERFUZZ_CACHE_DIR))

    self.assert_exact_calls(
        self.mock.update_auth_header, [mock.call()] * 2)
    self.assert_exact_calls(self.mock.send_run, [
        mock.call(1234, 'sanity', '0.2.2rc10', 'master', 'run_testcase',
                  'some logs', ''),
        mock.call(1234, 'sanity', '0.2.2rc10', 'master', 'run_testcase',
                  'some logs', '--current --skip-deps -i 20')
    ])
    self.assert_exact_calls(
        self.mock.prepare_binary_and_get_version, [mock.call('master')])
    self.mock.clean.assert_called_once_with()
    self.assert_exact_calls(self.mock.sleep, [
        mock.call('run_testcase'), mock.call('run_testcase')])


class SleepTest(helpers.ExtendedTestCase):
  """Tests sleep."""

  def setUp(self):
    helpers.patch(self, ['time.sleep', 'error.error.get_class'])

  def test_normal(self):
    """Tests normal sleep."""
    self.mock.get_class.return_value = error.UserRespondingNoError
    main.sleep(error.UserRespondingNoError.EXIT_CODE)
    self.mock.get_class.assert_called_once_with(
        error.UserRespondingNoError.EXIT_CODE)

  def test_minimization(self):
    """Tests minimization."""
    self.mock.get_class.return_value = error.MinimizationNotFinishedError
    main.sleep(error.MinimizationNotFinishedError.EXIT_CODE)
    self.mock.get_class.assert_called_once_with(
        error.MinimizationNotFinishedError.EXIT_CODE)


class BuildMasterAndGetVersionTest(helpers.ExtendedTestCase):
  """Tests the build_master_and_get_version method."""

  def setUp(self):
    helpers.patch(self, ['daemon.process.call',
                         'daemon.main.delete_if_exists',
                         'shutil.copy',
                         'os.path.exists'])
    self.mock.exists.return_value = False

  def test_run(self):
    """Tests checking out & building from master."""
    self.mock.call.return_value = (0, 'version')
    self.assertEqual('version', main.build_master_and_get_version())

    self.assert_exact_calls(self.mock.call, [
        mock.call('git clone https://github.com/google/clusterfuzz-tools.git',
                  cwd=main.HOME),
        mock.call('git fetch', cwd=main.TOOL_SOURCE),
        mock.call('git checkout origin/master -f', cwd=main.TOOL_SOURCE),
        mock.call('./pants binary tool:clusterfuzz-ci', cwd=main.TOOL_SOURCE,
                  env={'HOME': main.HOME}),
        mock.call('git rev-parse HEAD', capture=True, cwd=main.TOOL_SOURCE)
    ])
    self.assert_exact_calls(
        self.mock.delete_if_exists, [mock.call(main.BINARY_LOCATION)])
    self.assert_exact_calls(self.mock.copy, [
        mock.call(os.path.join(main.TOOL_SOURCE, 'dist', 'clusterfuzz-ci.pex'),
                  main.BINARY_LOCATION)
    ])


class DeleteIfExistsTest(helpers.ExtendedTestCase):
  """Tests delete_if_exists."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_not_exist(self):
    """test non-existing file."""
    main.delete_if_exists('/path/test')

  def test_dir(self):
    """Test deleting dir."""
    os.makedirs('/path/test')
    self.fs.CreateFile('/path/test/textfile', contents='yes')
    self.assertTrue(os.path.exists('/path/test'))
    self.assertTrue(os.path.exists('/path/test/textfile'))

    main.delete_if_exists('/path/test')
    self.assertFalse(os.path.exists('/path/test'))
    self.assertFalse(os.path.exists('/path/test/textfile'))

  def test_file(self):
    """Test deleting file."""
    self.fs.CreateFile('/path/test/textfile', contents='yes')
    self.assertTrue(os.path.exists('/path/test/textfile'))

    main.delete_if_exists('/path/test/textfile')
    self.assertFalse(os.path.exists('/path/test/textfile'))


class PrepareBinaryAndGetVersionTest(helpers.ExtendedTestCase):
  """Prepare binary and get version."""

  def setUp(self):
    helpers.patch(self, [
        'daemon.main.build_master_and_get_version',
        'daemon.main.get_binary_version'
    ])
    self.mock.build_master_and_get_version.return_value = 'vmaster'
    self.mock.get_binary_version.return_value = 'vbinary'

  def test_master(self):
    """Get version from master."""
    self.assertEqual('vmaster', main.prepare_binary_and_get_version('master'))

  def test_release(self):
    """Get version from release."""
    self.assertEqual(
        'vbinary', main.prepare_binary_and_get_version('release'))
    self.assertEqual(
        'vbinary', main.prepare_binary_and_get_version('release-candidate'))


class ReadLogsTest(helpers.ExtendedTestCase):
  """Test read_logs."""

  def setUp(self):
    # We can't use pyfakefs. Because pyfakefs' f.seek() results in a
    # different behaviour. See:
    # https://github.com/google/clusterfuzz-tools/issues/367
    self.tempfile = tempfile.NamedTemporaryFile(delete=False)
    self.tempfile.close()

  def tearDown(self):
    os.remove(self.tempfile.name)

  def test_file_not_exist(self):
    """Test file not exist."""
    self.another_tempfile = tempfile.NamedTemporaryFile(delete=True)
    self.another_tempfile.close()
    self.assertEqual(
        "%s doesn't exist." % self.another_tempfile.name,
        main.read_logs(self.another_tempfile.name))

  def test_small_file(self):
    """Test small file."""
    with open(self.tempfile.name, 'w') as f:
      f.write('some logs')
    self.assertIn('some logs', main.read_logs(self.tempfile.name))

  def test_large_file(self):
    """Test previewing a large file."""
    with open(self.tempfile.name, 'w') as f:
      f.write('a' * (main.MAX_PREVIEW_LOG_BYTE_COUNT + 10))
    self.assertIn(
        'a' * main.MAX_PREVIEW_LOG_BYTE_COUNT,
        main.read_logs(self.tempfile.name))
    self.assertNotIn(
        'a' * (main.MAX_PREVIEW_LOG_BYTE_COUNT + 1),
        main.read_logs(self.tempfile.name))


class CleanTest(helpers.ExtendedTestCase):
  """Test clean."""

  def setUp(self):
    self.setup_fake_filesystem()
    self.mock_os_environment({'PATH': 'some_path'})
    helpers.patch(self, ['daemon.process.call'])

  def test_clean(self):
    """Test clean every git repo."""
    main.clean()

    self.assert_exact_calls(self.mock.call, [
        mock.call('git clean -ffdd', cwd=main.CHROMIUM_SRC),
        mock.call('git reset --hard', cwd=main.CHROMIUM_SRC),
        mock.call('git add --all', cwd=main.CHROMIUM_SRC),
        mock.call('git reset --hard', cwd=main.CHROMIUM_SRC),
        mock.call('git checkout origin/master -f', cwd=main.CHROMIUM_SRC),
        mock.call('rm -rf testing', cwd=main.CHROMIUM_SRC),
        mock.call('git checkout origin/master testing -f',
                  cwd=main.CHROMIUM_SRC),
        mock.call('rm -rf third_party', cwd=main.CHROMIUM_SRC),
        mock.call('git checkout origin/master third_party -f',
                  cwd=main.CHROMIUM_SRC),
        mock.call('rm -rf tools', cwd=main.CHROMIUM_SRC),
        mock.call('git checkout origin/master tools -f', cwd=main.CHROMIUM_SRC),
        mock.call(
            'gclient sync --reset', cwd=main.CHROMIUM_SRC,
            env={'PATH': 'some_path:%s' % main.DEPOT_TOOLS}),
    ])


class IsTimeValidTest(helpers.ExtendedTestCase):
  """Tests is_time_valid."""

  def setUp(self):
    helpers.patch(self, ['time.time'])

  def test_valid(self):
    """Tests valid."""
    self.mock.time.return_value = main.MAX_AGE + 100
    self.assertTrue(main.is_time_valid(main.MAX_AGE - main.MIN_AGE))

  def test_too_new(self):
    """Tests too new."""
    self.mock.time.return_value = main.MAX_AGE + 100
    self.assertFalse(main.is_time_valid(main.MAX_AGE))

  def test_too_old(self):
    """Tests too old."""
    self.mock.time.return_value = main.MAX_AGE + 100
    self.assertFalse(main.is_time_valid(99))
