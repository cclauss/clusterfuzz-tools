"""Test the binary_providers module."""
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
import json
import mock

from clusterfuzz import binary_providers
from clusterfuzz import common
from clusterfuzz import output_transformer
from error import error
from tests import libs
from test_libs import helpers


class BuildRevisionToShaUrlTest(helpers.ExtendedTestCase):
  """Tests the build_revision_to_sha_url method."""

  def setUp(self):
    helpers.patch(self, [
        'urlfetch.fetch'])

  def test_correct_url_building(self):
    """Tests if the SHA url is built correctly"""

    result = binary_providers.build_revision_to_sha_url(12345, 'v8/v8')
    self.assertEqual(result, ('https://cr-rev.appspot.com/_ah/api/crrev/v1'
                              '/get_numbering?project=chromium&repo=v8%2Fv8'
                              '&number=12345&numbering_type='
                              'COMMIT_POSITION&numbering_identifier=refs'
                              '%2Fheads%2Fmaster'))


class ShaFromRevisionTest(helpers.ExtendedTestCase):
  """Tests the sha_from_revision method."""

  def setUp(self):
    helpers.patch(self, ['urlfetch.fetch'])

  def test_get_sha_from_response_body(self):
    """Tests to ensure that the sha is grabbed from the response correctly"""

    self.mock.fetch.return_value = mock.Mock(body=json.dumps({
        'id': 12345,
        'git_sha': '1a2s3d4f',
        'crash_type': 'Bad Crash'}))

    result = binary_providers.sha_from_revision(123456, 'v8/v8')
    self.assertEqual(result, '1a2s3d4f')


class GetThirdPartyShaTest(helpers.ExtendedTestCase):
  """Tests the get_third_party_sha method."""

  def setUp(self):
    helpers.patch(self, ['urlfetch.fetch'])
    self.mock.fetch.return_value = mock.Mock(
        body=('dmFycyA9IHsNCiAgJ3BkZml1bV9naXQnOiAnaHR0cHM6Ly9wZGZpdW0uZ29vZ'
              '2xlc291cmNlLmNvbScsDQogICdwZGZpdW1fcmV2aXNpb24nOiAnNDA5MzAzOW'
              'QxOWY4MzIxNzNlYzU4Y2ZkOWYyZThhYzM5M2E3NjA5MScsDQp9DQo='))

  def test_decode_pdfium_sha(self):
    """Tests if the method correctly grabs the sha from the b64 download."""

    result = binary_providers.get_third_party_sha(
        'chrome_sha', 'pdfium_revision')
    self.assert_exact_calls(self.mock.fetch, [mock.call(
        ('https://chromium.googlesource.com/chromium/src.git/+/chrome_sha'
         '/DEPS?format=TEXT'))])
    self.assertEqual(result, '4093039d19f832173ec58cfd9f2e8ac393a76091')


class DownloadBuildIfNeededTest(helpers.ExtendedTestCase):
  """Test download_build_if_needed."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.delete_if_exists',
        'clusterfuzz.common.execute',
        'clusterfuzz.common.gsutil',
        'clusterfuzz.common.find_file',
        'tempfile.mkdtemp',
        'shutil.copytree',
        'os.path.exists'
    ])

    self.dest_path = '/fake/dest'
    self.build_url = 'https://storage.cloud.google.com/test/test2/abc.zip'

  def test_already_download(self):
    """Tests the exit when build data is already returned."""
    self.mock.exists.return_value = True
    binary_providers.download_build_if_needed(
        self.dest_path, self.build_url)
    self.assert_n_calls(0, [self.mock.execute])

  def test_get_build_data(self):
    """Tests extracting, moving and renaming the build data.."""
    self.mock.exists.return_value = False
    self.mock.mkdtemp.return_value = '/tmp/random'
    self.mock.find_file.return_value = '/tmp/random/sub/args.gn'

    binary_providers.download_build_if_needed(
        self.dest_path, self.build_url)

    self.mock.execute.assert_called_once_with(
        'unzip', '-q %s -d %s' % (
            os.path.join(common.CLUSTERFUZZ_CACHE_DIR, 'abc.zip'),
            self.mock.mkdtemp.return_value),
        cwd='.'
    )
    self.assert_exact_calls(self.mock.delete_if_exists, [
        mock.call(os.path.join(common.CLUSTERFUZZ_CACHE_DIR, 'abc.zip')),
        mock.call(self.mock.mkdtemp.return_value),
    ])
    self.mock.copytree.assert_called_once_with(
        '/tmp/random/sub', self.dest_path)
    self.mock.gsutil.assert_called_once_with(
        'cp gs://test/test2/abc.zip .', common.CLUSTERFUZZ_CACHE_DIR)
    self.mock.find_file.assert_called_once_with(
        'args.gn', self.mock.mkdtemp.return_value)


class GetBinaryPathTest(helpers.ExtendedTestCase):
  """Tests the get_binary_path method."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.BinaryProvider.get_build_dir_path',
        'os.stat',
        'os.chmod'
    ])

  def test_call(self):
    """Tests calling the method."""
    self.mock.stat.return_value = mock.Mock(st_mode=0o600)

    build_dir = os.path.expanduser(os.path.join(
        '~', 'chrome_src', 'out', '12345_build'))
    self.mock.get_build_dir_path.return_value = build_dir

    provider = binary_providers.BinaryProvider(
        libs.make_testcase(testcase_id=12345, build_url='build_url'),
        libs.make_definition(binary_name='d8'),
        libs.make_options())

    path = os.path.join(build_dir, 'd8')
    self.assertEqual(path, provider.get_binary_path())
    self.mock.stat.assert_called_once_with(path)
    self.mock.chmod.assert_called_once_with(path, 0o700)


class DownloadedBinaryTest(helpers.ExtendedTestCase):
  """Test DownloadedBinary."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.download_build_if_needed',
        'clusterfuzz.binary_providers.get_or_ask_for_source_location',
        'clusterfuzz.binary_providers.BinaryProvider.get_binary_path',
    ])
    self.definition = libs.make_definition(binary_name='d8')
    self.testcase = libs.make_testcase(
        testcase_id=12345, build_url='https://storage.cloud.google.com/abc.zip')
    self.provider = binary_providers.DownloadedBinary(
        testcase=self.testcase, definition=self.definition,
        options=libs.make_options())

  def test_get_source_dir_path(self):
    """Test get_source_dir_path."""
    self.mock.get_or_ask_for_source_location.return_value = '/src'
    self.assertEqual('/src', self.provider.get_source_dir_path())

  def test_get_build_dir_path(self):
    """Test get_build_dir_path."""
    expected_path = os.path.join(
        common.CLUSTERFUZZ_BUILDS_DIR, '12345_downloaded_build')

    self.assertEqual(expected_path, self.provider.get_build_dir_path())
    self.mock.download_build_if_needed.assert_called_once_with(
        expected_path, self.testcase.build_url)

  def test_get_binary_path(self):
    """Tests get_binary_path."""
    self.mock.get_binary_path.return_value = 'binary'
    self.assertEqual('binary', self.provider.get_binary_path())
    self.mock.get_binary_path.assert_called_once_with(self.provider)

  def test_get_android_libclang_dir_path(self):
    """Tests get_binary_path."""
    helpers.patch(self, [
        'clusterfuzz.binary_providers.DownloadedBinary.get_build_dir_path'
    ])
    self.mock.get_build_dir_path.return_value = 'build/test'

    self.assertEqual(
        'build/test',
        self.provider.get_android_libclang_dir_path())

  def test_get_unstripped_lib_dir_path(self):
    """Tests get_unstripped_lib_dir_path."""
    helpers.patch(self, [
        'clusterfuzz.binary_providers.DownloadedBinary.get_build_dir_path'
    ])
    self.mock.get_build_dir_path.return_value = 'build/test'

    self.assertEqual(
        'build/test', self.provider.get_unstripped_lib_dir_path())


class GenericBuilderGetSourceDirPathTest(helpers.ExtendedTestCase):
  """Test GenericBuilder.get_source_dir_path."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.get_or_ask_for_source_location'
    ])
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(source_name='something'),
        libs.make_options())

  def test_get_from_user(self):
    """Test get the source location from user."""
    self.mock.get_or_ask_for_source_location.return_value = '/path'
    self.assertEqual('/path', self.builder.get_source_dir_path())
    self.mock.get_or_ask_for_source_location.assert_called_once_with(
        'something')


class GenericBuilderGetMainRepoPathTest(helpers.ExtendedTestCase):
  """Test GenericBuilder.get_main_repo_path."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path'
    ])
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(source_name='something'),
        libs.make_options())

  def test_get_from_user(self):
    """Test get the source location from user."""
    self.mock.get_source_dir_path.return_value = '/path'
    self.assertEqual('/path', self.builder.get_main_repo_path())
    self.mock.get_source_dir_path.assert_called_once_with(self.builder)


class GenericBuilderGetBuildDirPathTest(helpers.ExtendedTestCase):
  """Test GenericBuilder.get_build_dir_path."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path',
    ])
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(testcase_id='1234', revision='999'),
        libs.make_definition(), libs.make_options(current=False))

  def test_get(self):
    """Test get."""
    self.mock.get_source_dir_path.return_value = '/path'
    self.assertEqual(
        '/path/out/clusterfuzz_1234', self.builder.get_build_dir_path())


class GenericBuilderGetGnArgsTest(helpers.ExtendedTestCase):
  """Tests the setup_gn_args method."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.setup_debug_symbol_if_needed',
        'clusterfuzz.binary_providers.setup_gn_goma_params',
    ])
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(raw_gn_args='a=b\nc=d'),
        libs.make_definition(sanitizer='ASAN'),
        libs.make_options(current=False, enable_debug=True)
    )
    self.builder.extra_gn_args = {'e': 'f'}

    self.mock.setup_debug_symbol_if_needed.side_effect = lambda v, _1, _2: v
    self.mock.setup_gn_goma_params.side_effect = lambda v, _: v

  def test_get(self):
    """Test getting gn_args."""
    expected = {'a': 'b', 'c': 'd', 'e': 'f'}
    self.assertEqual(expected, self.builder.get_gn_args())

    self.mock.setup_gn_goma_params.assert_called_once_with(
        expected, False)
    self.mock.setup_debug_symbol_if_needed.assert_called_once_with(
        expected, 'ASAN', True)


class GenericBuilderGnGenTest(helpers.ExtendedTestCase):
  """Test gn_gen."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.common.edit_if_needed',
        'clusterfuzz.binary_providers.GenericBuilder.get_build_dir_path',
        'clusterfuzz.binary_providers.GenericBuilder.get_gn_args',
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path',
    ])
    self.setup_fake_filesystem()
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(),
        libs.make_options(edit_mode=True))

    self.mock.edit_if_needed.side_effect = (
        lambda content, prefix, comment, should_edit: content)

  def test_gn_gen(self):
    """Ensure args.gn is generated and gn gen is run."""
    os.makedirs('/test/build_dir')
    self.fs.CreateFile('/test/build_dir/args.gn', contents='random')

    self.mock.get_build_dir_path.return_value = '/test/build_dir'
    self.mock.get_gn_args.return_value = {'a': 'b'}
    self.mock.get_source_dir_path.return_value = '/chrome/source/dir'

    self.builder.gn_gen()

    with open('/test/build_dir/args.gn', 'r') as f:
      self.assertEqual(f.read(), 'a = b')
    self.mock.get_gn_args.assert_called_once_with(self.builder)
    self.mock.execute.assert_called_once_with(
        'gn', 'gen /test/build_dir', '/chrome/source/dir')
    self.mock.edit_if_needed.assert_called_once_with(
        'a = b', prefix=mock.ANY, comment=mock.ANY, should_edit=True)


class GenericBuilderInstallDepsTest(helpers.ExtendedTestCase):
  """Test gn_gen."""

  def setUp(self):
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(), libs.make_options())

  def test_install(self):
    """Test doing nothing."""
    self.builder.install_deps()


class GenericBuilderGclientSyncTest(helpers.ExtendedTestCase):
  """Test gclient_sync."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path',
    ])
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(), libs.make_options())

  def test_runhooks(self):
    """Test doing nothing"""
    self.mock.get_source_dir_path.return_value = '/src'
    self.builder.gclient_sync()
    self.mock.execute.assert_called_once_with(
        'gclient', 'sync', '/src', stdin=mock.ANY)


class GenericBuilderGclientRunhooksTest(helpers.ExtendedTestCase):
  """Test gn_gen."""

  def setUp(self):
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(), libs.make_options())

  def test_runhooks(self):
    """Test doing nothing"""
    self.builder.gclient_runhooks()


class GenericBuilderSetupAllDepsTest(helpers.ExtendedTestCase):
  """Test GenericBuilder.setup_all_deps."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, [
        'clusterfuzz.binary_providers.GenericBuilder.gclient_sync',
        'clusterfuzz.binary_providers.GenericBuilder.gclient_runhooks',
        'clusterfuzz.binary_providers.GenericBuilder.install_deps',
    ])

  def test_skip(self):
    """Test skip."""
    builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(),
        libs.make_options(skip_deps=True))
    builder.setup_all_deps()
    self.assert_n_calls(0, [
        self.mock.gclient_sync,
        self.mock.gclient_runhooks,
        self.mock.install_deps])

  def test_run(self):
    """Test run."""
    builder = binary_providers.GenericBuilder(
        libs.make_testcase(), libs.make_definition(),
        libs.make_options(skip_deps=False))
    builder.setup_all_deps()
    self.mock.gclient_sync.assert_called_once_with(builder)
    self.mock.gclient_runhooks.assert_called_once_with(builder)
    self.mock.install_deps.assert_called_once_with(builder)


class GenericBuilderGetTargetNameAndBinaryNameTest(helpers.ExtendedTestCase):
  """Test get_target_name and get_binary_name."""

  def setUp(self):
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(),
        libs.make_definition(binary_name='binary', targets=['d8']),
        libs.make_options())

  def test_get_target_name(self):
    """Test get_target_name."""
    self.assertEqual(['d8'], self.builder.get_target_names())

  def test_get_binary_name(self):
    """Test get_binary_name."""
    self.assertEqual('binary', self.builder.get_binary_name())


class GenericBuilderBuildTest(helpers.ExtendedTestCase):
  """Test build inside the V8DownloadedBinary class."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.GenericBuilder.setup_all_deps',
        'clusterfuzz.binary_providers.GenericBuilder.gn_gen',
        'clusterfuzz.binary_providers.GenericBuilder.get_git_sha',
        'clusterfuzz.binary_providers.GenericBuilder.get_build_dir_path',
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path',
        'clusterfuzz.binary_providers.compute_goma_cores',
        'clusterfuzz.binary_providers.compute_goma_load',
        'clusterfuzz.binary_providers.git_checkout',
        'clusterfuzz.common.execute',
    ])
    self.builder = binary_providers.GenericBuilder(
        libs.make_testcase(revision=213), libs.make_definition(targets=['d8']),
        libs.make_options(current=False))

  def test_build(self):
    """Test build"""
    self.mock.get_build_dir_path.return_value = (
        '/chrome/source/out/clusterfuzz_54321')
    self.mock.get_source_dir_path.return_value = '/chrome/source'
    self.mock.compute_goma_cores.return_value = 120
    self.mock.compute_goma_load.return_value = 8
    self.mock.get_git_sha.return_value = 'sha'

    self.builder.build()

    self.mock.git_checkout.assert_called_once_with('sha', 213, '/chrome/source')
    self.mock.setup_all_deps.assert_called_once_with(self.builder)
    self.mock.gn_gen.assert_called_once_with(self.builder)
    self.mock.execute.assert_called_once_with(
        'ninja',
        ("-w 'dupbuild=err' -C /chrome/source/out/clusterfuzz_54321 "
         '-j 120 -l 8 d8'),
        '/chrome/source',
        capture_output=False,
        stdout_transformer=mock.ANY)
    self.assertIsInstance(
        self.mock.execute.call_args[1]['stdout_transformer'],
        output_transformer.Ninja)


class DeserializeGnArgsTest(helpers.ExtendedTestCase):
  """Test deserialize_gn_args."""

  def test_empty(self):
    """Test empty args."""
    self.assertEqual({}, binary_providers.deserialize_gn_args(''))
    self.assertEqual({}, binary_providers.deserialize_gn_args(None))

  def test_deserialize(self):
    """Test deserialize."""
    self.assertEqual(
        {'a': '"b"', 'c': '1'},
        binary_providers.deserialize_gn_args('a = "b"\nc=1'))


class GitCheckoutTest(helpers.ExtendedTestCase):
  """Tests the git_checkout method."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.common.check_confirm',
        'clusterfuzz.binary_providers.ensure_sha',
        'clusterfuzz.binary_providers.get_current_sha',
        'clusterfuzz.binary_providers.sha_from_revision',
        'clusterfuzz.binary_providers.is_repo_dirty',
    ])
    self.source = '/usr/local/google/home/user/repos/chromium/src'
    self.revision = 4567
    self.sha = '1a2s3d4f'

  def test_dirty_dir(self):
    """Tests when the correct git sha is not already checked out."""
    self.mock.get_current_sha.return_value = 'aaa'
    self.mock.is_repo_dirty.return_value = True
    with self.assertRaises(error.DirtyRepoError):
      binary_providers.git_checkout(self.sha, self.revision, self.source)

    self.mock.get_current_sha.assert_called_once_with(self.source)
    self.mock.check_confirm.assert_called_once_with(
        binary_providers.CHECKOUT_MESSAGE.format(
            revision=4567,
            cmd='git checkout %s' % self.sha,
            source_dir=self.source))

  def test_confirm_checkout(self):
    """Tests when user wants confirm the checkout."""
    self.mock.get_current_sha.return_value = 'aaa'
    self.mock.is_repo_dirty.return_value = False
    binary_providers.git_checkout(self.sha, self.revision, self.source)

    self.mock.get_current_sha.assert_called_once_with(self.source)
    self.mock.execute.assert_called_once_with(
        'git', 'checkout 1a2s3d4f', self.source)
    self.mock.check_confirm.assert_called_once_with(
        binary_providers.CHECKOUT_MESSAGE.format(
            revision=4567,
            cmd='git checkout %s' % self.sha,
            source_dir=self.source))

  def test_already_checked_out(self):
    """Tests when the correct git sha is already checked out."""
    self.mock.get_current_sha.return_value = '1a2s3d4f'
    binary_providers.git_checkout(self.sha, self.revision, self.source)

    self.mock.get_current_sha.assert_called_once_with(self.source)
    self.assert_n_calls(0, [self.mock.check_confirm, self.mock.execute])


class EnsureShaTest(helpers.ExtendedTestCase):
  """Tests ensure_sha."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.binary_providers.sha_exists',
    ])

  def test_already_exists(self):
    """Test when sha already exists."""
    self.mock.sha_exists.return_value = True
    binary_providers.ensure_sha('sha', 'source')

    self.mock.sha_exists.assert_called_once_with('sha', 'source')
    self.assertEqual(0, self.mock.execute.call_count)

  def test_not_exists(self):
    """Test when sha doesn't exists."""
    self.mock.sha_exists.return_value = False
    binary_providers.ensure_sha('sha', 'source')

    self.mock.sha_exists.assert_called_once_with('sha', 'source')
    self.mock.execute.assert_called_once_with(
        'git', 'fetch origin sha', 'source')


class PdfiumBuilderGetGitShaTest(helpers.ExtendedTestCase):
  """Test PdfiumBuilder.get_git_sha."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.sha_from_revision',
        'clusterfuzz.binary_providers.get_third_party_sha'])
    self.builder = binary_providers.PdfiumBuilder(
        libs.make_testcase(revision=1234), libs.make_definition(),
        libs.make_options())

  def test_get_git_sha(self):
    """Test get_git_sha."""
    self.mock.sha_from_revision.return_value = 'sha'
    self.mock.get_third_party_sha.return_value = 'pdfium_sha'

    self.assertEqual('pdfium_sha', self.builder.get_git_sha())
    self.mock.sha_from_revision.assert_called_once_with(1234, 'chromium/src')
    self.mock.get_third_party_sha.assert_called_once_with(
        'sha', 'pdfium_revision')


class ChromiumBuilderTest(helpers.ExtendedTestCase):
  """Test ChromiumBuilder.get_git_sha."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.install_build_deps',
        'clusterfuzz.binary_providers.sha_from_revision',
        'clusterfuzz.common.execute',
        'clusterfuzz.binary_providers.get_binary_name',
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path'
    ])
    self.mock.get_source_dir_path.return_value = '/src'
    self.builder = binary_providers.ChromiumBuilder(
        libs.make_testcase(revision=1234), libs.make_definition(binary_name=''),
        libs.make_options())

  def test_get_git_sha(self):
    """Test get_git_sha."""
    self.mock.sha_from_revision.return_value = 'sha'
    self.assertEqual('sha', self.builder.get_git_sha())
    self.mock.sha_from_revision.assert_called_once_with(1234, 'chromium/src')

  def test_install_deps(self):
    """Test install_deps."""
    self.builder.install_deps()
    self.mock.install_build_deps.assert_called_once_with(
        '/src', include_lib32=False)
    self.mock.execute.assert_called_once_with(
        'python', 'tools/clang/scripts/update.py', '/src')

  def test_gclient_runhooks(self):
    """Test gclient_runhooks."""
    self.mock.get_source_dir_path.return_value = '/src'
    self.builder.gclient_runhooks()
    self.mock.execute.assert_called_once_with(
        'gclient', 'runhooks', '/src')


class V8BuilderTest(helpers.ExtendedTestCase):
  """Test methods in V8Builder"""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.GenericBuilder.get_source_dir_path',
        'clusterfuzz.binary_providers.sha_from_revision',
        'clusterfuzz.binary_providers.get_third_party_sha',
        'clusterfuzz.binary_providers.install_build_deps',
        'clusterfuzz.common.execute',
    ])
    self.mock.get_source_dir_path.return_value = '/src'
    self.builder = binary_providers.V8Builder(
        libs.make_testcase(revision=1234), libs.make_definition(),
        libs.make_options())

  def test_get_git_sha_standalone(self):
    """Test get_git_sha for standalone."""
    self.mock.sha_from_revision.return_value = 'sha'
    self.assertEqual('sha', self.builder.get_git_sha())
    self.mock.sha_from_revision.assert_called_once_with(1234, 'v8/v8')

  def test_get_git_sha_from_chromium(self):
    """Test get_git_sha for standalone."""
    self.builder.testcase.revision = 400001
    self.mock.sha_from_revision.return_value = 'sha'
    self.mock.get_third_party_sha.return_value = 'third_party_sha'
    self.assertEqual('third_party_sha', self.builder.get_git_sha())
    self.mock.sha_from_revision.assert_called_once_with(400001, 'chromium/src')
    self.mock.get_third_party_sha.assert_called_once_with('sha', 'v8_revision')

  def test_install_deps(self):
    """Test install_deps."""
    self.builder.install_deps()
    self.mock.install_build_deps.assert_called_once_with(
        '/src', include_lib32=False)
    self.mock.execute.assert_called_once_with(
        'python', 'tools/clang/scripts/update.py', '/src')

  def test_gclient_runhooks(self):
    """Test gclient_runhooks."""
    self.builder.gclient_runhooks()
    self.mock.execute.assert_called_once_with('gclient', 'runhooks', '/src')


class CfiMixinTest(helpers.ExtendedTestCase):
  """Tests CfiMixin."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.binary_providers.sha_from_revision',
        'clusterfuzz.binary_providers.ChromiumBuilder.install_deps',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_source_dir_path',
        'os.path.exists'
    ])
    self.mock.get_source_dir_path.return_value = '/chrome/src'
    self.builder = binary_providers.CfiChromiumBuilder(
        libs.make_testcase(), libs.make_definition(), libs.make_options())

  def test_install_deps(self):
    """Test install deps."""
    self.mock.exists.return_value = True
    self.builder.install_deps()
    self.mock.execute.assert_called_once_with(
        'build/download_gold_plugin.py', '', '/chrome/src')
    self.mock.exists.assert_called_once_with(
        '/chrome/src/build/download_gold_plugin.py')
    self.mock.install_deps.assert_called_once_with(self.builder)

  def test_not_install_deps(self):
    """Test NOT install deps."""
    self.mock.exists.return_value = False
    self.builder.install_deps()
    self.assertEqual(0, self.mock.execute.call_count)
    self.mock.exists.assert_called_once_with(
        '/chrome/src/build/download_gold_plugin.py')
    self.mock.install_deps.assert_called_once_with(self.builder)


class MsanMixinTest(helpers.ExtendedTestCase):
  """Tests MsanMixin."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.ChromiumBuilder.get_gn_args',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_source_dir_path',
        'clusterfuzz.binary_providers.ChromiumBuilder.gclient_runhooks',
        'clusterfuzz.binary_providers.gclient_runhooks_msan',
    ])
    self.builder = binary_providers.MsanChromiumBuilder(
        libs.make_testcase(), libs.make_definition(), libs.make_options())

  def test_gclient_runhooks(self):
    """Test gclient runhooks."""
    self.mock.get_gn_args.return_value = {'msan_track_origins': '1'}
    self.mock.get_source_dir_path.return_value = '/chrome/src'
    self.builder.gclient_runhooks()
    self.mock.gclient_runhooks_msan.assert_called_once_with('/chrome/src', '1')
    # It's important that the super class's gclient_runhooks isn't invoked.
    self.assertEqual(0, self.mock.gclient_runhooks.call_count)


class Lib32MixinTest(helpers.ExtendedTestCase):
  """Tests ChromiumBuilder32Bit."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.install_build_deps',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_source_dir_path',
        'clusterfuzz.binary_providers.ChromiumBuilder.install_deps',
    ])
    self.mock.get_source_dir_path.return_value = '/chrome/src'
    self.builder = binary_providers.ChromiumBuilder32Bit(
        libs.make_testcase(), libs.make_definition(), libs.make_options())

  def test_install_deps(self):
    """Test the install_deps method."""
    self.builder.install_deps()
    self.assertTrue(self.builder.include_lib32)
    self.mock.install_deps.assert_called_once_with(self.builder)


class GetCurrentShaTest(helpers.ExtendedTestCase):
  """Tests functionality when the rev-parse command fails."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.binary_providers.sha_from_revision'
    ])
    self.mock.execute.return_value = (0, 'test\n')

  def test_get(self):
    """Tests to ensure the method prints before it exits."""
    self.assertEqual('test', binary_providers.get_current_sha('source'))
    self.mock.execute.assert_called_once_with(
        'git', 'rev-parse HEAD', 'source', print_command=False,
        print_output=False)


class ComputeGomaCoresTest(helpers.ExtendedTestCase):
  """Tests to ensure the correct number of cores is set."""

  def setUp(self):
    helpers.patch(self, ['multiprocessing.cpu_count'])
    self.mock.cpu_count.return_value = 64

  def test_specifying_goma_threads(self):
    """Ensures that if cores are manually specified, they are used."""
    self.assertEqual(binary_providers.compute_goma_cores(500, False), 500)

  def test_not_specifying_goma_threads(self):
    """Test not specifying goma threads."""
    self.assertEqual(binary_providers.compute_goma_cores(None, False), 3200)

  def test_disable_goma(self):
    """Test disabling goma."""
    self.assertEqual(binary_providers.compute_goma_cores(None, True), 48)


class ComputeGomaLoadTest(helpers.ExtendedTestCase):
  """Test compute_goma_load"""

  def setUp(self):
    helpers.patch(self, ['multiprocessing.cpu_count'])
    self.mock.cpu_count.return_value = 64

  def test_specifying(self):
    """Ensures that if cores are manually specified, they are used."""
    self.assertEqual(binary_providers.compute_goma_load(500), 500)

  def test_not_specifying(self):
    """Test not specifying."""
    self.assertEqual(binary_providers.compute_goma_load(None), 128)


class ShaExistsTest(helpers.ExtendedTestCase):
  """Tests for sha_exists."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_exist(self):
    """Test exists."""
    self.mock.execute.return_value = (0, '')
    self.assertTrue(binary_providers.sha_exists('SHA', '/dir'))

    self.mock.execute.assert_called_once_with(
        'git', 'cat-file -e SHA', cwd='/dir', exit_on_error=False)

  def test_not_exist(self):
    """Test not exists."""
    self.mock.execute.return_value = (1, '')
    self.assertFalse(binary_providers.sha_exists('SHA', '/dir'))

    self.mock.execute.assert_called_once_with(
        'git', 'cat-file -e SHA', cwd='/dir', exit_on_error=False)


class IsRepoDirtyTest(helpers.ExtendedTestCase):
  """Tests for is_repo_dirty."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_clean(self):
    """Test exists."""
    self.mock.execute.return_value = (0, '')
    self.assertFalse(binary_providers.is_repo_dirty('/dir'))

    self.mock.execute.assert_called_once_with(
        'git', 'diff', '/dir', print_command=True, print_output=True)

  def test_dirty(self):
    """Test not exists."""
    self.mock.execute.return_value = (0, 'some change')
    self.assertTrue(binary_providers.is_repo_dirty('/dir'))

    self.mock.execute.assert_called_once_with(
        'git', 'diff', '/dir', print_command=True, print_output=True)


class SetupDebugSymbolIfNeededTest(helpers.ExtendedTestCase):
  """Tests setup_debug_symbol_if_needed."""

  def test_not_setup(self):
    """Test when we shouldn't setup debug symbol."""
    self.assertEqual(
        {'is_debug': 'false'},
        binary_providers.setup_debug_symbol_if_needed(
            {'is_debug': 'false'}, 'ASAN', False))

  def test_asan(self):
    """Test editing."""
    self.assertEqual(
        {'symbol_level': '2', 'is_debug': 'true',
         'sanitizer_keep_symbols': 'true'},
        binary_providers.setup_debug_symbol_if_needed(
            {'is_debug': 'false'}, 'ASAN', True))

  def test_msan(self):
    """Test editing."""
    self.assertEqual(
        {'symbol_level': '2', 'is_debug': 'false',
         'sanitizer_keep_symbols': 'true'},
        binary_providers.setup_debug_symbol_if_needed(
            {'is_debug': 'false'}, 'MSAN', True))


class InstallBuildDepsTest(helpers.ExtendedTestCase):
  """Tests install_build_deps."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_build_32bit(self):
    """Test run."""
    binary_providers.install_build_deps('/source', include_lib32=True)
    self.mock.execute.assert_called_once_with(
        'sudo',
        'PATH=$PATH build/install-build-deps.sh --syms --no-prompt --lib32',
        '/source', stdout_transformer=mock.ANY, preexec_fn=None,
        redirect_stderr_to_stdout=True)
    self.assertIsInstance(
        self.mock.execute.call_args[1]['stdout_transformer'],
        output_transformer.Identity)


class GclientRunhooksMsanTest(helpers.ExtendedTestCase):
  """Tests gclient_runhooks_msan."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_run(self):
    """Test run."""
    binary_providers.gclient_runhooks_msan('source', '4')
    self.mock.execute.assert_called_once_with(
        'gclient', 'runhooks', 'source',
        env={
            'GYP_DEFINES': (
                'msan=1 msan_track_origins=4 '
                'use_prebuilt_instrumented_libraries=1')
        }
    )

  def test_no_origin(self):
    """Test no origin."""
    binary_providers.gclient_runhooks_msan('source', '')
    self.mock.execute.assert_called_once_with(
        'gclient', 'runhooks', 'source',
        env={
            'GYP_DEFINES': (
                'msan=1 msan_track_origins=2 '
                'use_prebuilt_instrumented_libraries=1')
        }
    )


class SetupGnGomaParamsTest(helpers.ExtendedTestCase):
  """Tests setup_gn_goma_params."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.binary_providers.ensure_goma'])

  def test_disable(self):
    """Test enabling goma"""
    self.assertEqual(
        {'use_goma': 'false', 'a': 'b'},
        binary_providers.setup_gn_goma_params({'a': 'b'}, disable_goma=True))
    self.assertEqual(0, self.mock.ensure_goma.call_count)

  def test_enable(self):
    """Test read from file."""
    self.mock.ensure_goma.return_value = '/path'
    self.assertEqual(
        {'use_goma': 'true', 'goma_dir': '"/path"', 'a': 'b'},
        binary_providers.setup_gn_goma_params({'a': 'b'}, disable_goma=False))
    self.mock.ensure_goma.assert_called_once_with()


class EnsureGomaTest(helpers.ExtendedTestCase):
  """Tests the ensure_goma method."""

  def setUp(self):
    self.setup_fake_filesystem()
    self.mock_os_environment(
        {'GOMA_DIR': os.path.expanduser(os.path.join('~', 'goma'))})
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_goma_not_installed(self):
    """Tests what happens when GOMA is not installed."""

    with self.assertRaises(error.GomaNotInstalledError) as ex:
      binary_providers.ensure_goma()
      self.assertTrue('goma is not installed' in ex.message)

  def test_goma_installed(self):
    """Tests what happens when GOMA is installed."""

    goma_dir = os.path.expanduser(os.path.join('~', 'goma'))
    os.makedirs(goma_dir)
    f = open(os.path.join(goma_dir, 'goma_ctl.py'), 'w')
    f.close()

    result = binary_providers.ensure_goma()

    self.assert_exact_calls(self.mock.execute, [
        mock.call('python', 'goma_ctl.py ensure_start', goma_dir)
    ])
    self.assertEqual(result, goma_dir)


class LibfuzzerAndAflBuilderTest(helpers.ExtendedTestCase):
  """Test LibfuzzerAndAflBuilder's methods."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.binary_providers.get_binary_name'])
    self.builder = binary_providers.LibfuzzerAndAflBuilder(
        libs.make_testcase(stacktrace_lines='trace'), libs.make_definition(),
        libs.make_options())
    self.mock.get_binary_name.return_value = 'target'

  def test_get_target_names(self):
    """Test get_target_names."""
    self.assertEqual(['target'], self.builder.get_target_names())
    self.mock.get_binary_name.assert_called_once_with('trace', False)

  def test_get_binary_name(self):
    """Test get_binary_name."""
    self.assertEqual('target', self.builder.get_binary_name())
    self.mock.get_binary_name.assert_called_once_with('trace', False)


class GetBinaryNameTest(helpers.ExtendedTestCase):
  """Test get_binary_name."""

  def test_running_command(self):
    """Test 'Running Command: '."""
    binary_name = binary_providers.get_binary_name([
        {'content': 'aaa'},
        {'content': 'Running command: aaa/bbb/some_fuzzer something'},
        {'content': 'bbb'}
    ])
    self.assertEqual('some_fuzzer', binary_name)

  def test_no_command(self):
    """Raise an exception when there's no command."""
    with self.assertRaises(error.MinimizationNotFinishedError):
      binary_providers.get_binary_name([{'content': 'aaa'}])


class GetSourceDirectoryTest(helpers.ExtendedTestCase):
  """Tests the get_source_directory method."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, [
        'clusterfuzz.common.ask',
        'clusterfuzz.binary_providers.check_gclient_managed'
    ])
    self.source_dir = '~/chromium/src'

  def test_get_from_environment(self):
    """Tests getting the source directory from the os environment."""

    self.mock_os_environment({'CHROMIUM_SRC': self.source_dir})
    result = binary_providers.get_or_ask_for_source_location('chromium')

    self.assertEqual(result, self.source_dir)
    self.assertEqual(0, self.mock.ask.call_count)
    self.mock.check_gclient_managed.assert_called_once_with(self.source_dir)

  def test_ask_and_expand_user(self):
    """Tests getting the source directory and expand user."""

    self.mock_os_environment({'CHROMIUM_SRC': ''})
    os.makedirs(os.path.expanduser('~/test-dir'))
    self.mock.ask.return_value = '~/test-dir'

    result = binary_providers.get_or_ask_for_source_location('chromium')
    self.assertEqual(os.path.expanduser('~/test-dir'), result)
    self.mock.check_gclient_managed.assert_called_once_with(
        os.path.expanduser('~/test-dir'))

  def test_ask_and_expand_path(self):
    """Tests getting the source directory and expand abspath."""

    self.mock_os_environment({'CHROMIUM_SRC': ''})
    os.makedirs(os.path.abspath('./test-dir'))
    self.mock.ask.return_value = './test-dir'

    result = binary_providers.get_or_ask_for_source_location('chromium')
    self.assertEqual(os.path.abspath('./test-dir'), result)
    self.mock.check_gclient_managed.assert_called_once_with(
        os.path.abspath('./test-dir'))


class ClankiumBuilderTest(helpers.ExtendedTestCase):
  """Tests ClankiumBuilder's methods."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.binary_providers.get_clank_sha',
        'clusterfuzz.common.execute',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_source_dir_path',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_build_dir_path',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_binary_name',
        'clusterfuzz.binary_providers.ChromiumBuilder.install_deps',
        'clusterfuzz.binary_providers.ChromiumBuilder.get_gn_args',
    ])
    self.builder = binary_providers.ClankiumBuilder(
        libs.make_testcase(revision='1234'),
        libs.make_definition(revision_url='test_url/%s'),
        libs.make_options())

  def test_get_git_sha(self):
    """Tests get_git_sha."""
    self.mock.get_clank_sha.return_value = 'clank-sha'
    self.assertEqual('clank-sha', self.builder.get_git_sha())

    self.mock.get_clank_sha.assert_called_once_with('test_url/1234')

  def test_get_main_repo_path(self):
    """Tests get_main_repo_path."""
    self.mock.get_source_dir_path.return_value = 'main-repo/src'
    self.assertEqual('main-repo/src/clank', self.builder.get_main_repo_path())

    self.mock.get_source_dir_path.assert_called_once_with(self.builder)

  def test_get_binary_path(self):
    """Tests get_binary_path."""
    self.mock.get_build_dir_path.return_value = 'build-dir'
    self.mock.get_binary_name.return_value = 'test.apk'

    self.assertEqual('build-dir/apks/test.apk', self.builder.get_binary_path())

  def test_unstripped_lib_dir_path(self):
    """Tests get_unstripped_lib_dir_path."""
    self.mock.get_build_dir_path.return_value = '/build'

    self.assertEqual(
        os.path.join('/build', 'lib.unstripped'),
        self.builder.get_unstripped_lib_dir_path())

  def test_get_android_libclang_dir_path(self):
    """Tests get_android_libclang_dir_path."""
    helpers.patch(self, ['os.listdir'])
    self.mock.get_source_dir_path.return_value = 'source'
    self.mock.listdir.return_value = ['6.0.0']

    self.assertEqual(
        os.path.join(
            'source', 'third_party', 'llvm-build',
            'Release+Asserts', 'lib', 'clang', '6.0.0', 'lib', 'linux'),
        self.builder.get_android_libclang_dir_path())

  def test_install_deps(self):
    """Tests install_deps.sh."""
    self.builder.install_deps()
    self.mock.install_deps.assert_called_once_with(self.builder)
    self.mock.execute.assert_called_once_with(
        'sudo', 'PATH=$PATH build/install-build-deps-android.sh',
        self.builder.get_source_dir_path(), stdout_transformer=mock.ANY,
        preexec_fn=None, redirect_stderr_to_stdout=True)

  def test_get_gn_args(self):
    """Tests getting gn args."""
    self.mock.get_gn_args.return_value = {'target_cpu': '"x86"'}
    args = self.builder.get_gn_args()
    self.assertEqual({'target_cpu': '"arm"'}, args)


class GetClankShaTest(helpers.ExtendedTestCase):
  """Tests get_clank_sha."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.gsutil'])
    self.setup_fake_filesystem()

  def test_get(self):
    """Tests get_clank_sha."""
    self.path = None
    def write_tmp_file(cmd, cwd):  # pylint: disable=unused-argument
      _, _, self.path = cmd.split(' ')
      with open(self.path, 'w') as f:
        f.write(
            'vars = {\n'
            '  "clank_revision": "aaffADB098",\n'
            '  "chromium_revision": "487843",\n'
            '}\n')
    self.mock.gsutil.side_effect = write_tmp_file

    self.assertEqual('aaffADB098', binary_providers.get_clank_sha('url/12345'))
    self.mock.gsutil.assert_called_once_with(
        'cp url/12345 %s' % self.path, cwd='.')

  def test_error(self):
    """Tests get_clank_sha."""
    self.path = None
    def write_tmp_file(cmd, cwd):  # pylint: disable=unused-argument
      _, _, self.path = cmd.split(' ')
      with open(self.path, 'w') as f:
        f.write(
            'vars = {\n'
            '  "chromium_revision": "487843",\n'
            '}\n')
    self.mock.gsutil.side_effect = write_tmp_file

    with self.assertRaises(Exception):
      binary_providers.get_clank_sha('url/12345')

    self.mock.gsutil.assert_called_once_with(
        'cp url/12345 %s' % self.path, cwd='.')


class CheckGclientManagedTest(helpers.ExtendedTestCase):
  """Tests check_gclient_managed."""

  def setUp(self):
    self.setup_fake_filesystem()

  def test_has_managed(self):
    """Tests .gclient contains managed=True."""
    self.fs.CreateFile(
        '/chromium/.gclient',
        contents=(
            'solutions = [\n'
            '  {\n'
            '    "managed":    True,\n'
            '  },\n'
            ']'))

    with self.assertRaises(error.GclientManagedEnabledException):
      binary_providers.check_gclient_managed('/chromium/src')

  def test_no_managed(self):
    """Tests .gclient contains managed=False."""
    self.fs.CreateFile(
        '/chromium/.gclient',
        contents=(
            'solutions = [\n'
            '  {\n'
            '    "managed":    False,\n'
            '  },\n'
            ']'))

    binary_providers.check_gclient_managed('/chromium/src')

  def test_no_gclient(self):
    """Tests no .gclient."""
    binary_providers.check_gclient_managed('/chromium/src')
