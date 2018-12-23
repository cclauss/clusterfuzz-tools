"""Module for the 'reproduce' command.

Locally reproduces a testcase given a ClusterFuzz ID."""
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
import time
import urllib
import webbrowser
import logging
import yaml

from clusterfuzz import common
from clusterfuzz import stackdriver_logging
from clusterfuzz import testcase
from clusterfuzz import binary_providers
from clusterfuzz import reproducers
from error import error


CLUSTERFUZZ_AUTH_HEADER = 'x-clusterfuzz-authorization'
CLUSTERFUZZ_AUTH_IDENTITY = 'x-clusterfuzz-identity'
CLUSTERFUZZ_TESTCASE_INFO_URL = (
    'https://%s/testcase-detail/refresh' % common.DOMAIN_NAME)
GOOGLE_OAUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth?%s' % (
    urllib.urlencode({
        'scope': 'email profile',
        'client_id': ('981641712411-sj50drhontt4m3gjc3hordjmp'
                      'c7bn50f.apps.googleusercontent.com'),
        'response_type': 'code',
        'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob'}))
RETRY_COUNT = 5
logger = logging.getLogger('clusterfuzz')


class SuppressOutput(object):
  """Suppress stdout and stderr. We need this because there's no way to suppress
    webbrowser's stdout and stderr."""

  def __enter__(self):
    self.stdout = os.dup(1)
    self.stderr = os.dup(2)
    os.close(1)
    os.close(2)
    os.open(os.devnull, os.O_RDWR)

  def __exit__(self, unused_type, unused_value, unused_traceback):
    os.dup2(self.stdout, 1)
    os.dup2(self.stderr, 2)
    return True


def get_verification_header():
  """Prompts the user for & returns a verification token."""
  print
  logger.info(('We need to authenticate you in order to get information from '
               'ClusterFuzz.'))
  print

  logger.info('Open: %s', GOOGLE_OAUTH_URL)
  with SuppressOutput():
    webbrowser.open(GOOGLE_OAUTH_URL, new=1, autoraise=True)
  print

  verification = common.ask(
      'Please login using the above URL and get your verification code',
      'Please enter the verification code', bool)
  return 'VerificationCode %s' % verification


def send_request(url, data):
  """Get a clusterfuzz url that requires authentication.

  Attempts to authenticate and is guaranteed to either
  return a valid, authorized response or throw an exception."""
  header = common.get_stored_auth_header() or get_verification_header()
  response = None
  for _ in range(RETRY_COUNT):
    response = common.post(
        url=url,
        headers={
            'Authorization': header,
            'User-Agent': 'clusterfuzz-tools'
        },
        data=data,
        allow_redirects=True)

    # The access token expired.
    if response.status_code == 401:
      header = get_verification_header()
    # Internal server error (e.g. due to deployment)
    elif response.status_code == 500:
      time.sleep(common.RETRY_SLEEP_TIME)
      continue
    else:  # Other errors or success
      break

  if response.status_code != 200:
    raise error.ClusterFuzzError(
        response.status_code, response.text,
        str(response.headers.get(CLUSTERFUZZ_AUTH_IDENTITY, '')))

  common.store_auth_header(response.headers[CLUSTERFUZZ_AUTH_HEADER])
  return response


def get_testcase_and_identity(testcase_id, force=False):
  """Pulls testcase information from ClusterFuzz.

  Returns a dictionary with the JSON response if the
  authentication is successful.
  """
  logger.info('Downloading testcase information...')
  data = json.dumps({'testcaseId': testcase_id})
  try:
    resp = send_request(CLUSTERFUZZ_TESTCASE_INFO_URL, data)
    return (testcase.create(json.loads(resp.text), force),
            resp.headers[CLUSTERFUZZ_AUTH_IDENTITY])
  except error.ClusterFuzzError as e:
    if e.status_code == 404:
      raise error.InvalidTestcaseIdError(testcase_id)
    elif e.status_code == 403 or e.status_code == 401:
      raise error.UnauthorizedError(testcase_id, e.identity)
    else:
      raise e


def parse_job_definition(job_definition, presets):
  """Reads in a job definition hash and parses it."""

  to_return = {}
  if 'preset' in job_definition:
    to_return = parse_job_definition(presets[job_definition['preset']], presets)
  for key, val in job_definition.iteritems():
    if key == 'preset':
      continue
    to_return[key] = val

  return to_return


def build_definition(job_definition, presets):
  """Converts a job definition hash into a binary definition."""

  # TODO(tanin): use the full class name in the YAML and eliminate this dict.
  builders = {
      'CfiChromium': binary_providers.CfiChromiumBuilder,
      'Chromium_32': binary_providers.ChromiumBuilder32Bit,
      'Chromium': binary_providers.ChromiumBuilder,
      'Clankium': binary_providers.ClankiumBuilder,
      'MsanChromium': binary_providers.MsanChromiumBuilder,
      'MsanV8': binary_providers.MsanV8Builder,
      'CfiV8': binary_providers.CfiV8Builder,
      'Pdfium': binary_providers.PdfiumBuilder,
      'V8': binary_providers.V8Builder,
      'V8_32': binary_providers.V8Builder32Bit,
      'Afl': binary_providers.LibfuzzerAndAflBuilder,
      'Libfuzzer': binary_providers.LibfuzzerAndAflBuilder,
      'LibfuzzerMsanChromium': binary_providers.LibfuzzerMsanBuilder
  }
  reproducer_map = {'Base': reproducers.BaseReproducer,
                    'LibfuzzerJob': reproducers.LibfuzzerJobReproducer,
                    'LinuxChromeJob': reproducers.LinuxChromeJobReproducer,
                    'Android': reproducers.AndroidChromeReproducer,
                    'AndroidWebView': reproducers.AndroidWebViewReproducer}

  result = parse_job_definition(job_definition, presets)

  return common.Definition(
      builder=builders[result['builder']],
      source_name=result['source_name'],
      reproducer=reproducer_map[result['reproducer']],
      binary_name=result.get('binary'),
      sanitizer=result['sanitizer'],
      targets=result.get('targets'),
      require_user_data_dir=result.get('require_user_data_dir', False),
      revision_url=result.get('revision_url', None))


def get_supported_jobs():
  """Reads in supported jobs from supported_jobs.yml."""

  to_return = {
      'standalone': {},
      'chromium': {}}

  with open(common.get_resource(
      0o640, 'resources', 'supported_job_types.yml')) as stream:
    job_types_yaml = yaml.load(stream)

  for build_type in ['standalone', 'chromium']:
    for job_type, job_definition in job_types_yaml[build_type].iteritems():
      try:
        to_return[build_type][job_type] = build_definition(
            job_definition, job_types_yaml['presets'])
      except KeyError as e:
        raise error.BadJobTypeDefinitionError(
            '%s %s (%s)' % (build_type, job_type, e))

  return to_return


def get_definition(job_type, testcase_id, build_param):
  """Get definition."""
  supported_jobs = get_supported_jobs()
  if build_param == 'download' or not build_param:
    builds = ['chromium', 'standalone']
  else:
    builds = [build_param]

  for build in builds:
    if job_type in supported_jobs[build]:
      return supported_jobs[build][job_type]

  raise error.JobTypeNotSupportedError(job_type, testcase_id)


def warn_unreproducible_if_needed(current_testcase):
  """Print warning if the testcase is unreproducible."""
  if current_testcase.gestures:
    print
    logger.info(common.colorize(
        'WARNING: the testcase is using gestures and inherently flaky. '
        "Therefore, we cannot guarantee that it'll reproduce correctly.",
        common.BASH_YELLOW_MARKER))
  if not current_testcase.reproducible:
    print
    logger.info(common.colorize(
        'WARNING: the testcase is marked as unreproducible. Therefore, it '
        'might not be reproduced.',
        common.BASH_YELLOW_MARKER))


def create_builder_class(build, definition):
  """Create a builder class. This reduces redundant code. For example,
    LibfuzzerAndAflBuilder's methods can be used with downloaded build and
    locally-built build."""
  types = []
  if build == 'download':
    types.append(binary_providers.DownloadedBinary)
  types.append(definition.builder)

  name = ''.join([t.__name__ for t in types])
  return type(name, tuple(types), {})


@stackdriver_logging.log
def execute(testcase_id, current, build, disable_goma, goma_threads, goma_load,
            iterations, disable_xvfb, target_args, edit_mode, skip_deps,
            enable_debug, extra_log_params, force):
  """Execute the reproduce command."""
  options = common.Options(
      testcase_id=testcase_id,
      current=current,
      build=build,
      disable_goma=disable_goma,
      goma_threads=goma_threads,
      goma_load=goma_load,
      iterations=iterations,
      disable_xvfb=disable_xvfb,
      target_args=target_args,
      edit_mode=edit_mode,
      skip_deps=skip_deps,
      enable_debug=enable_debug,
      extra_log_params=extra_log_params, force=force)

  logger.info('Reproducing testcase %s', testcase_id)
  logger.debug('%s', str(options))

  common.ensure_important_dirs()

  current_testcase, identity = get_testcase_and_identity(testcase_id, force)
  extra_log_params['identity'] = identity
  extra_log_params['job_type'] = current_testcase.job_type
  extra_log_params['platform'] = current_testcase.platform
  extra_log_params['reproducible'] = current_testcase.reproducible
  # A hack to download testcase early. Otherwise, OAuth access token might
  # expire after compiling (~1h).
  current_testcase.get_testcase_path()
  definition = get_definition(current_testcase.job_type, testcase_id, build)

  warn_unreproducible_if_needed(current_testcase)

  binary_provider = create_builder_class(build, definition)(
      testcase=current_testcase,
      definition=definition,
      options=options)
  binary_provider.build()

  reproducer = definition.reproducer(
      definition=definition,
      binary_provider=binary_provider,
      testcase=current_testcase,
      sanitizer=definition.sanitizer,
      options=options)
  try:
    reproducer.reproduce(iterations)
  finally:
    warn_unreproducible_if_needed(current_testcase)
