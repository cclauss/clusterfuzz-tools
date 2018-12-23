"""Classes to reproduce different types of testcases."""
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

import HTMLParser
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time

import psutil
import xvfbwrapper

from clusterfuzz import android
from clusterfuzz import common
from clusterfuzz import output_transformer
from error import error

DISABLE_GL_DRAW_ARG = '--disable-gl-drawing-for-tests'
DEFAULT_GESTURE_TIME = 5
TEST_TIMEOUT = 30
USER_DATA_DIR_PATH = '/tmp/clusterfuzz-user-data-dir'
USER_DATA_DIR_ARG = '--user-data-dir'
ANDROID_SERIAL_ENV = 'ANDROID_SERIAL'
SYSTEM_WEBVIEW_DIRS = [
    '/system/app/webview',
    '/system/app/WebViewGoogle',
]
SYSTEM_WEBVIEW_PACKAGE = 'com.google.android.webview'
SYSTEM_WEBVIEW_VMSIZE_BYTES = 250 * 1000 * 1000
SYSTEM_WEBVIEW_APK = 'SystemWebViewGoogle.apk'

# A testcase created after 6 Aug 2017 doesn't need the layout test hack.
LAYOUT_HACK_CUTOFF_DATE_IN_SECONDS = time.mktime((2017, 8, 11, 0, 0, 0, 0, 0,
                                                  0))

MONKEY_THROTTLE_DELAY = 100
NUM_MONKEY_EVENTS = 50
ANDROID_TESTCASE_DIR = '/sdcard/clusterfuzz'

logger = logging.getLogger('clusterfuzz')


def strip_html(lines):
  """Strip HTML tags and escape HTML chars."""
  new_lines = []
  parser = HTMLParser.HTMLParser()

  for line in lines:
    # We only strip <a> because that's all we need.
    line = re.sub('<[/a][^<]+?>', '', line)
    new_lines.append(parser.unescape(line))

  return new_lines


def get_only_first_stacktrace(lines):
  """Get the first stacktrace because multiple stacktraces would make stacktrace
    parsing wrong."""
  new_lines = []
  found_first_stack = False
  for line in lines:
    line = line.rstrip()
    if line.startswith('+----'):
      if found_first_stack:
        # This is the second stack, ignore everything from now on.
        break

      found_first_stack = True

    # We don't add the empty lines in the beginning.
    if new_lines or line:
      new_lines.append(line)

  return new_lines


def maybe_fix_dict_args(args, build_dir):
  """Fix the dict args of libfuzzer args if exists."""
  dict_path = args.get('dict')
  if dict_path:
    args['dict'] = os.path.join(build_dir, os.path.basename(dict_path))
  return args


def deserialize_libfuzzer_args(args_str):
  """Deserialize libfuzzer's args, e.g. -dict=something."""
  args = {}
  for kvs in args_str.split(' '):
    kvs = kvs.strip()
    if not kvs:
      continue
    tokens = kvs.split('=')
    args[tokens[0].lstrip('-')] = tokens[1]
  return args


def serialize_libfuzzer_args(args):
  """Serialize a dict to libfuzzer's args, e.g. -dict=something."""
  args_list = []
  for key, value in args.iteritems():
    args_list.append('-%s=%s' % (key, value))

  return ' '.join(sorted(args_list))


def is_similar(new_signature, original_signature):
  """Check if the new state is similar enough to the original state."""
  count = 0
  if new_signature.crash_type == original_signature.crash_type:
    count += 1

  for line in new_signature.crash_state_lines:
    if line in original_signature.crash_state_lines:
      count += 1

  return count >= len(original_signature.crash_state_lines)


def deserialize_sanitizer_options(options):
  """Read options from a variable like ASAN_OPTIONS into a dict."""
  pairs = options.split(':')
  return_dict = {}
  for pair in pairs:
    k, v = pair.split('=')
    return_dict[k] = v
  return return_dict


def serialize_sanitizer_options(options):
  """Takes dict of sanitizer options, returns command-line friendly string."""
  pairs = []
  for key, value in options.iteritems():
    pairs.append('%s=%s' % (key, value))
  return ':'.join(pairs)


def ensure_user_data_dir_if_needed(args, require_user_data_dir):
  """Ensure the right user-data-dir."""
  if not require_user_data_dir and USER_DATA_DIR_ARG not in args:
    return args

  # Remove --user-data-dir-arg if exist.
  args = re.sub('%s[^ ]+' % USER_DATA_DIR_ARG, '', args)
  common.delete_if_exists(USER_DATA_DIR_PATH)
  return '%s %s=%s' % (args, USER_DATA_DIR_ARG, USER_DATA_DIR_PATH)


# TODO(#463): Remove on 11 Nov 2017.
def update_testcase_path_in_layout_test(testcase_path, original_testcase_path,
                                        source_directory, testcase_created_at):
  """Update the testcase path if it's a layout test."""
  search_string = '%sLayoutTests%s' % (os.sep, os.sep)
  if (testcase_created_at >= LAYOUT_HACK_CUTOFF_DATE_IN_SECONDS or
      search_string not in original_testcase_path):
    return testcase_path

  # Move testcase to LayoutTests directory if needed.
  search_index = original_testcase_path.find(search_string)
  new_testcase_path = os.path.join(
      source_directory, 'third_party', 'WebKit', 'LayoutTests',
      original_testcase_path[search_index + len(search_string):])
  shutil.copy(testcase_path, new_testcase_path)
  return new_testcase_path


def update_for_gdb_if_needed(binary_path, args, timeout, should_enable_gdb):
  """Update binary_path, args, and timeout if gdb is enabled."""
  if not should_enable_gdb:
    return binary_path, args, timeout

  args = "-ex 'b __sanitizer::Die' -ex run --args %s %s" % (binary_path, args)
  return 'gdb', args, None


def get_crash_signature(job_type, raw_stacktrace):
  """Get crash signature from raw_stacktrace by asking ClusterFuzz."""
  response = common.post(
      url='https://clusterfuzz.com/parse_stacktrace',
      data=json.dumps({
          'job': job_type,
          'stacktrace': raw_stacktrace
      }))
  response = json.loads(response.text)
  crash_state_lines = tuple(
      [x for x in response['crash_state'].split('\n') if x])
  crash_type = response['crash_type'].replace('\n', ' ')
  return common.CrashSignature(crash_type, crash_state_lines)


def symbolize(output, source_dir_path):
  """Symbolize a stacktrace."""
  output = output.strip()
  if not output:
    # If no input, nothing to symbolize. Bail out, otherwise
    # we hang inside symbolizer.
    return ''

  asan_symbolizer_location = os.path.join(
      source_dir_path,
      os.path.join('tools', 'valgrind', 'asan', 'asan_symbolize.py'))
  symbolizer_proxy_location = common.get_resource(0o755,
                                                  'asan_symbolize_proxy.py')

  _, symbolized_out = common.execute(
      asan_symbolizer_location,
      '',
      os.path.expanduser('~'),
      env={
          'LLVM_SYMBOLIZER_PATH': symbolizer_proxy_location,
          'CHROMIUM_SRC': source_dir_path
      },
      capture_output=True,
      exit_on_error=True,
      stdout_transformer=output_transformer.Identity(),
      stdin=common.StringStdin(output + '\0'),
      redirect_stderr_to_stdout=True)
  logger.info(symbolized_out)
  return symbolized_out


def set_device_id_if_possible():
  """Get the device ID if there's only one."""
  if os.environ.get(ANDROID_SERIAL_ENV):
    return

  _, output = android.adb('devices')
  device_lines = output.strip().splitlines()[1:]

  if len(device_lines) == 1:
    os.environ[ANDROID_SERIAL_ENV] = re.split(r'\s+', device_lines[0])[0]


def run_monkey_gestures_if_needed(package_name, gestures):
  """Runs monkey gestures if gestures isn't empty."""
  if not gestures:
    return

  gestures = gestures[0].split(',')

  if gestures[0] != 'monkey':
    return

  seed = gestures[-1]
  android.adb_shell(
      'monkey -p %s -s %s --throttle %s --ignore-security-exceptions %s' %
      (package_name, seed, MONKEY_THROTTLE_DELAY, NUM_MONKEY_EVENTS))
  time.sleep(10)


class BaseReproducer(object):
  """The basic reproducer class that all other ones are built on."""

  def get_gesture_start_time(self):
    """Determine how long to sleep before running gestures."""

    if self.gestures[-1].startswith('Trigger'):
      gesture_start_time = int(self.gestures[-1].split(':')[1])
      self.gestures.pop()
    else:
      gesture_start_time = DEFAULT_GESTURE_TIME
    return gesture_start_time

  def __init__(self, definition, binary_provider, testcase, sanitizer, options):
    self.definition = definition
    self.testcase = testcase
    self.binary_provider = binary_provider
    self.sanitizer = sanitizer
    self.options = options
    # TODO(tanin): remove these attributes. We shouldn't forward the
    # attributes.
    self.original_testcase_path = testcase.absolute_path
    self.job_type = testcase.job_type
    self.environment = testcase.environment
    self.args = testcase.reproduction_args
    # TODO(tanin): remove these attributes. We shouldn't forward the
    # attributes.
    self.binary_path = binary_provider.get_binary_path()
    self.build_directory = binary_provider.get_build_dir_path()
    self.source_directory = binary_provider.get_source_dir_path()
    self.symbolizer_path = common.get_resource(0o755, 'resources',
                                               'llvm-symbolizer')
    self.gestures = testcase.gestures
    self.timeout = TEST_TIMEOUT

    self.gesture_start_time = (
        self.get_gesture_start_time() if self.gestures else None)

  def set_up_symbolizers_suppressions(self):
    """Sets up the symbolizer variables for an environment."""

    env = self.environment
    env['%s_SYMBOLIZER_PATH' % self.sanitizer] = self.symbolizer_path
    env['DISPLAY'] = ':0.0'
    for variable in env:
      if '_OPTIONS' not in variable:
        continue
      options = deserialize_sanitizer_options(env[variable])

      if 'external_symbolizer_path' in options:
        options['external_symbolizer_path'] = self.symbolizer_path
      options.pop('coverage_dir', None)
      if 'suppressions' in options:
        suppressions_map = {
            'CFI_OPTIONS': 'ubsan',
            'LSAN_OPTIONS': 'lsan',
            'TSAN_OPTIONS': 'tsan',
            'UBSAN_OPTIONS': 'ubsan',
        }
        filename = common.get_resource(
            0o640, 'resources', 'suppressions',
            '%s_suppressions.txt' % suppressions_map[variable])
        options['suppressions'] = filename
      env[variable] = serialize_sanitizer_options(options)
    self.environment = env

  def pre_build_steps(self):
    """Steps to run before building."""
    self.set_up_symbolizers_suppressions()
    self.setup_args()

    # Ensure the testcase is setup correctly at the right path.
    self.get_testcase_path()

  def reproduce_crash(self):
    """Reproduce the crash."""
    # read_buffer_length needs to be 1, and stdin needs to be UserStdin.
    # Otherwise, it wouldn't work well with gdb.
    return common.execute(
        self.binary_path,
        self.args,
        self.build_directory,
        env=self.environment,
        exit_on_error=False,
        timeout=self.timeout,
        stdout_transformer=output_transformer.Identity(),
        redirect_stderr_to_stdout=True,
        stdin=common.UserStdin(),
        read_buffer_length=1)

  @common.memoize
  def get_testcase_path(self):
    """Get the testcase path. This allows subclasses to perform necessary
      operations to modify testcase path."""
    return self.testcase.get_testcase_path()

  @common.memoize
  def get_testcase_url(self):
    """Get the testcase URL. In android, this is different from testcase
      path."""
    return 'file://%s' % self.get_testcase_path()

  @common.memoize
  def get_crash_signature(self):
    """Post a stacktrace, return (crash_state, crash_type)."""
    stacktrace_lines = strip_html(
        [l['content'] for l in self.testcase.stacktrace_lines])
    stacktrace_lines = get_only_first_stacktrace(stacktrace_lines)
    return get_crash_signature(self.job_type, '\n'.join(stacktrace_lines))

  def setup_args(self):
    """Setup args."""
    # Add custom args if any.
    # TODO(tanin): refactor the condition to its own module function.
    if self.options.target_args:
      self.args += ' %s' % self.options.target_args

    # --disable-gl-drawing-for-tests does not draw gl content on screen.
    # When running in regular mode, user would want to see screen, so
    # remove this argument.
    # TODO(tanin): refactor the condition to its own module function.
    if self.options.disable_xvfb and DISABLE_GL_DRAW_ARG in self.args:
      self.args = self.args.replace(' %s' % DISABLE_GL_DRAW_ARG, '')
      self.args = self.args.replace(DISABLE_GL_DRAW_ARG, '')

    # Replace build directory environment variable.
    self.args = self.args.replace('%APP_DIR%', self.build_directory)

    # Use %TESTCASE% argument if available. Otherwise append testcase path.
    # TODO(tanin): refactor the condition to its own module function.
    if '%TESTCASE%' in self.args:
      self.args = self.args.replace('%TESTCASE%', self.get_testcase_path())
    elif '%TESTCASE_FILE_URL%' in self.args:
      self.args = self.args.replace('%TESTCASE_FILE_URL%',
                                    self.get_testcase_path())
    else:
      self.args += ' %s' % self.get_testcase_path()

    self.binary_path, self.args, self.timeout = update_for_gdb_if_needed(
        self.binary_path, self.args, self.timeout, self.options.enable_debug)
    self.args = common.edit_if_needed(
        self.args,
        prefix='edit-args-',
        comment='Edit arguments before running %s' % self.binary_path,
        should_edit=self.options.edit_mode)

  def reproduce_debug(self):
    """Reproduce with debugger."""
    self.reproduce_crash()
    return True

  def reproduce_normal(self, iteration_max):
    """Reproduce normally."""
    iterations = 1
    signatures = set()
    has_signature = False
    while iterations <= iteration_max:
      _, output = self.reproduce_crash()

      new_signature = get_crash_signature(self.job_type, output)
      new_signature.output = output
      signatures.add(new_signature)

      has_signature = (
          bool(new_signature.crash_type) or
          bool(new_signature.crash_state_lines))
      logger.info('New crash type: %s\n'
                  'New crash state:\n  %s\n\n'
                  'Original crash type: %s\n'
                  'Original crash state:\n  %s\n', new_signature.crash_type,
                  '\n  '.join(new_signature.crash_state_lines),
                  self.get_crash_signature().crash_type, '\n  '.join(
                      self.get_crash_signature().crash_state_lines))

      # The crash signature validation is intentionally forgiving.
      if is_similar(new_signature, self.get_crash_signature()):
        logger.info(
            common.colorize(
                'The stacktrace seems similar to the original stacktrace.\n'
                "Since you've reproduced the crash correctly, there are some "
                'tricks that might help you move faster:\n'
                '- In case of fixing the crash, you can use `--current` to run '
                'on tip-of-tree (or, in other words, avoid git-checkout).\n'
                '- You can save time by using `--skip-deps` to avoid '
                '`gclient sync`, `gclient runhooks`, and other dependency '
                'installations in subsequential runs.\n'
                '- You can debug with gdb using `--enable-debug`.\n'
                '- You can modify args.gn and arguments using `--edit-mode`.',
                common.BASH_GREEN_MARKER))
        return True
      else:
        logger.info("The stacktrace doesn't match the original stacktrace.")
        logger.info('Try again (%d times). Press Ctrl+C to stop trying to '
                    'reproduce.', iterations)
      iterations += 1
      time.sleep(3)

    if has_signature:
      raise error.DifferentStacktraceError(iteration_max, signatures)
    else:
      raise error.UnreproducibleError(iteration_max, signatures)

  # TODO(tanin): Remove iteration_max and use self.options.iterations.
  def reproduce(self, iteration_max):
    """Reproduces the crash and prints the stacktrace."""
    logger.info('Reproducing...')

    self.pre_build_steps()

    if self.options.enable_debug:
      return self.reproduce_debug()
    else:
      return self.reproduce_normal(iteration_max)


class LibfuzzerJobReproducer(BaseReproducer):
  """A reproducer for libfuzzer job types."""

  def pre_build_steps(self):
    """Steps to run before building."""
    args = deserialize_libfuzzer_args(self.args)
    maybe_fix_dict_args(args, os.path.dirname(self.binary_path))
    self.args = serialize_libfuzzer_args(args)

    super(LibfuzzerJobReproducer, self).pre_build_steps()


class Xvfb(object):
  """Run commands within a virtual display using blackbox window manager."""

  def __init__(self, disable=False):
    self.disable_xvfb = disable

  def __enter__(self):
    if self.disable_xvfb:
      return None
    self.display = xvfbwrapper.Xvfb(width=1280, height=1024)
    self.display.start()
    for i in self.display.xvfb_cmd:
      if i.startswith(':'):
        display_name = i
        break
    logger.info('Starting the blackbox window manager in a virtual display.')
    try:
      self.blackbox = subprocess.Popen(
          ['blackbox'], env={
              'DISPLAY': display_name
          })
    except OSError as e:
      if str(e) == '[Errno 2] No such file or directory':
        raise error.NotInstalledError('blackbox')
      raise

    time.sleep(3)
    return display_name

  def __exit__(self, unused_type, unused_value, unused_traceback):
    if self.disable_xvfb:
      return
    self.blackbox.kill()
    self.display.stop()


class LinuxChromeJobReproducer(BaseReproducer):
  """Adds and extre pre-build step to BaseReproducer."""

  def get_process_ids(self, process_id, recursive=True):
    """Return list of pids for a process and its descendants."""

    # Try to find the running process.
    if not psutil.pid_exists(process_id):
      return []

    pids = [process_id]
    try:
      psutil_handle = psutil.Process(process_id)
      children = psutil_handle.children(recursive=recursive)
      for child in children:
        pids.append(child.pid)
    except:
      logger.info('psutil: Process abruptly ended.')
      raise

    return pids

  def xdotool_command(self, command, display_name):
    """Run a command, returning its output."""
    common.execute(
        'xdotool',
        command,
        '.',
        env={'DISPLAY': display_name},
        stdin=common.BlockStdin())

  def find_windows_for_process(self, process_id, display_name):
    """Return visible windows belonging to a process."""
    pids = self.get_process_ids(process_id)
    if not pids:
      return []

    logger.info('Waiting for 30 seconds to ensure all windows appear: '
                'pid=%s, display=%s', pids, display_name)
    time.sleep(30)

    visible_windows = set()
    for pid in pids:
      _, windows = common.execute(
          'xdotool',
          'search --all --pid %s --onlyvisible --name ".*"' % pid,
          '.',
          env={'DISPLAY': display_name},
          exit_on_error=False,
          print_command=False,
          print_output=False,
          stdin=common.BlockStdin())
      for line in windows.splitlines():
        if not line.isdigit():
          continue
        visible_windows.add(line)

    logger.info('Found windows: %s', ', '.join(list(visible_windows)))
    return visible_windows

  def execute_gesture(self, gesture, window, display_name):
    """Executes a specific gesture."""

    gesture_type, gesture_cmd = gesture.split(',')
    if gesture_type == 'windowsize':
      self.xdotool_command('%s %s %s' % (gesture_type, window, gesture_cmd),
                           display_name)
    else:
      self.xdotool_command('%s -- %s' % (gesture_type, gesture_cmd),
                           display_name)

  def run_gestures(self, proc, display_name):
    """Executes all required gestures."""

    time.sleep(self.gesture_start_time)
    logger.info('Running gestures...')
    windows = self.find_windows_for_process(proc.pid, display_name)
    for _, window in enumerate(windows):
      logger.info('Run gestures on window %s', window)
      self.xdotool_command('windowactivate --sync %s' % window, display_name)

      for gesture in self.gestures:
        self.execute_gesture(gesture, window, display_name)

  @common.memoize
  def get_testcase_path(self):
    """Get testcase path."""
    return update_testcase_path_in_layout_test(
        self.testcase.get_testcase_path(), self.original_testcase_path,
        self.source_directory, self.testcase.created_at)

  def pre_build_steps(self):
    """Steps to run before building."""
    # TODO(tanin): Move this to get_args.
    self.args = ensure_user_data_dir_if_needed(
        self.args, self.definition.require_user_data_dir)
    # TODO(tanin): Move this to get_testcase_path.

    self.environment.pop('ASAN_SYMBOLIZER_PATH', None)
    super(LinuxChromeJobReproducer, self).pre_build_steps()

  def reproduce_crash(self):
    """Reproduce the crash, running gestures if necessary."""

    with Xvfb(self.options.disable_xvfb) as display_name:
      self.environment['DISPLAY'] = display_name

      # stdin needs to be UserStdin. Otherwise, it wouldn't work with gdb.
      process = common.start_execute(
          self.binary_path,
          self.args,
          self.build_directory,
          env=self.environment,
          stdin=common.UserStdin(),
          redirect_stderr_to_stdout=True)

      if self.gestures:
        self.run_gestures(process, display_name)

      # read_buffer_length needs to be 1. Otherwise, it wouldn't work well with
      # gdb.
      err, out = common.wait_execute(
          process,
          exit_on_error=False,
          timeout=self.timeout,
          stdout_transformer=output_transformer.Identity(),
          read_buffer_length=1)
      return err, symbolize(out, self.source_directory)


class AndroidChromeReproducer(BaseReproducer):
  """Reproduce an android chromium job type."""

  def reproduce_debug(self):
    """Reproduce with GDB isn't supported in Android."""
    raise error.GdbNotSupportedOnAndroidError()

  @common.memoize
  def get_device_id(self):
    """Get the android device."""
    set_device_id_if_possible()
    device_id = os.environ.get(ANDROID_SERIAL_ENV)

    if not device_id:
      raise error.NoAndroidDeviceIdError(ANDROID_SERIAL_ENV)

    return device_id

  @common.memoize
  def get_testcase_path(self):
    """Get the testcase path."""
    android.adb_shell('rm -rf %s' % ANDROID_TESTCASE_DIR)
    android_testcase_dir = '%s/%s' % (ANDROID_TESTCASE_DIR, self.testcase.id)

    testcase_relative_path = os.path.relpath(self.testcase.get_testcase_path(),
                                             self.testcase.testcase_dir_path)
    android.adb('push %s %s' % (self.testcase.testcase_dir_path,
                                android_testcase_dir))

    return '%s/%s' % (android_testcase_dir, testcase_relative_path)

  def install(self):
    """Instal chrome on Android."""
    android.uninstall(self.testcase.android_package_name)
    android.install(self.binary_path)

  def pre_build_steps(self):
    """Pre-build step."""
    # Ensure that the user sets ANDROID_SERIAL. Because adb uses it.
    device_id = self.get_device_id()
    android.ensure_root_and_remount()
    android.ensure_active()
    android.ensure_asan(
        android_libclang_dir_path=(
            self.binary_provider.get_android_libclang_dir_path()),
        device_id=device_id)

    super(AndroidChromeReproducer, self).pre_build_steps()

    for path, content in self.testcase.files.iteritems():
      android.write_content(path, content)
    android.write_content(self.testcase.command_line_file_path,
                          'chrome %s' % self.args)
    self.install()

  def reproduce_crash(self):
    """Reproduce crash on Android."""
    android.reset(self.testcase.android_package_name)
    android.reboot()
    android.ensure_active()
    android.clear_log()

    ret_value, _ = android.adb_shell(
        'am start -a android.intent.action.MAIN '
        "-n {package_name}/{class_name} '{testcase_url}'".format(
            package_name=self.testcase.android_package_name,
            class_name=self.testcase.android_main_class_name,
            testcase_url=self.get_testcase_url()),
        redirect_stderr_to_stdout=True,
        stdout_transformer=output_transformer.Identity())
    time.sleep(TEST_TIMEOUT)

    run_monkey_gestures_if_needed(self.testcase.android_package_name,
                                  self.testcase.gestures)

    output = android.get_log()
    android.kill(self.testcase.android_package_name)

    lib_tmp_dir_path = tempfile.mkdtemp(dir=common.CLUSTERFUZZ_TMP_DIR)
    symbolized_output = symbolize(
        output=android.fix_lib_path(
            content=android.filter_log(output),
            search_paths=[
                self.binary_provider.get_unstripped_lib_dir_path(),
                self.binary_provider.get_android_libclang_dir_path()
            ],
            lib_tmp_dir_path=lib_tmp_dir_path),
        source_dir_path=self.binary_provider.get_source_dir_path())
    common.delete_if_exists(lib_tmp_dir_path)
    return ret_value, symbolized_output


class AndroidWebViewReproducer(AndroidChromeReproducer):
  """Reproduce an android webview job type."""

  def install(self):
    """Install webview."""
    android.adb_shell(
        'setprop persist.sys.webview.vmsize %s' % SYSTEM_WEBVIEW_VMSIZE_BYTES)
    android.adb_shell('stop')
    android.adb_shell('rm -rf %s' % ' '.join(SYSTEM_WEBVIEW_DIRS))
    android.adb_shell('start')
    android.uninstall(SYSTEM_WEBVIEW_PACKAGE)
    android.uninstall(self.testcase.android_package_name)
    android.install(
        os.path.join(os.path.dirname(self.binary_path), SYSTEM_WEBVIEW_APK))
    android.install(self.binary_path)
