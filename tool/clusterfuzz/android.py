"""Methods for managing an android device."""

import logging
import os
import re
import tempfile
import time

from clusterfuzz import common
from clusterfuzz import output_transformer
from error import error


ANDROID_LIBRARY_EXTENSION = '.so'
ASAN_BEING_INSTALLED_SEARCH_STRING = 'Please wait until the device restarts'
DM_VERITY_ENABLED_STRING = 'dm_verity is enabled'
BOOT_TIMEOUT = 600
BOOT_WAIT_INTERVAL = 10
SCREEN_LOCK_SEARCH_STRING = 'mShowingLockscreen=true'


logger = logging.getLogger('clusterfuzz')


def adb(command, **kwargs):
  """Run adb with command."""
  return common.execute('adb', command, cwd='.', **kwargs)


def adb_shell(command, **kwargs):
  """Run adb shell with command."""
  escaped_command = command.replace('\\', '\\\\').replace('"', r'\"')
  return adb('shell "%s"' % escaped_command, **kwargs)


def uninstall(package_name):
  """Uninstall the package_name."""
  return adb(
      'uninstall %s' % package_name, redirect_stderr_to_stdout=True,
      exit_on_error=False)


def install(apk_path):
  """Install an apk. We need this method to detect failure."""
  returncode, output = adb(
      'install -r %s' % apk_path, redirect_stderr_to_stdout=True)

  if 'failure' in output.lower() or 'failed' in output.lower():
    raise error.CommandFailedError('adb install -r %s' % apk_path, -1, output)
  return returncode, output


def write_content(path, content):
  """Write content to path on Android."""
  with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
    tmp_file.write(content)

  logger.info(
      common.colorize(
          '\nWriting %s:\n%s\n', common.BASH_GREEN_MARKER),
      path, content)

  adb('push %s %s' % (tmp_file.name, path))
  adb_shell('chmod 0644 %s' % path)
  common.delete_if_exists(tmp_file.name)


def ensure_asan(android_libclang_dir_path, device_id):
  """Ensures ASan is installed on Android."""
  logger.info(
      'The testcase needs ASAN. After installing ASAN, the device might be '
      'restarted.')

  common.check_confirm(
      'Are you sure you want to install ASAN on the device %s?' % device_id)

  _, output = common.execute(
      common.get_resource(0o755, 'resources', 'asan_device_setup.sh'),
      '--lib %s --device %s' % (android_libclang_dir_path, device_id),
      env={'ADB_PATH': common.check_binary('adb', cwd='.')},
      redirect_stderr_to_stdout=True,
      cwd='.')

  # tool/clusterfuzz/resources/asan_device_setup.sh prints the below string
  # when it modifies asan configuration on device. So, wait for the reboot to
  # be complete.
  if ASAN_BEING_INSTALLED_SEARCH_STRING in output:
    wait_until_fully_booted()


def convert_android_crash_stack_line(line):
  """Convert Android's crash stack line into sanitizer_format."""
  m_crash_state = re.match(
      r'\s*#([0-9]+)\s+pc\s+([xX0-9a-fA-F]+)\s+(.+)', line)
  if not m_crash_state:
    return None

  frame_no = int(m_crash_state.group(1))
  frame_address = m_crash_state.group(2)
  frame_binary = m_crash_state.group(3).strip()

  # Ignore invalid frames, helps to prevent errors
  # while symbolizing.
  if '<unknown>' in frame_binary:
    return None

  # Normalize frame address.
  if not frame_address.startswith('0x'):
    frame_address = '0x%s' % frame_address

  # Seperate out the function argument.
  frame_binary = (frame_binary.split(' '))[0]

  # Normalize line into the same sanitizer tool format.
  return '    #%d %s (%s+%s)' % (
      frame_no, frame_address, frame_binary, frame_address)


def convert_chrome_crash_stack_line(line):
  """Convert Chrome crash stack line into the sanitizer format."""
  # Stack frames don't have paranthesis around frame binary and address, so
  # add it explicitly to allow symbolizer to catch it.
  m_crash_state = re.match(
      r'\s*#([0-9]+)\s+([xX0-9a-fA-F]+)\s+([^(]+\+[xX0-9a-fA-F]+)$', line)
  if not m_crash_state:
    return

  frame_no = int(m_crash_state.group(1))
  frame_address = m_crash_state.group(2)
  frame_binary_and_address = m_crash_state.group(3).strip()
  return '    #%d %s (%s)' % (
      frame_no, frame_address, frame_binary_and_address)


def get_process_id_and_name(header):
  """Get process id from header."""
  m_process_num = re.match(r'(.*)[(]\s*(\d+)[)]', header)
  if not m_process_num:
    return None

  return int(m_process_num.group(2)), m_process_num.group(1).strip()


def filter_log(content):
  """Filter adb logs."""
  if not content:
    return ''
  filtered_output = ''
  last_process_id = 0
  for line in content.splitlines():
    # Discard noisy debug output.
    # http://developer.android.com/tools/debugging/debugging-log.html.
    m_line = re.match('[^D]/([^:]+)[:] (.*)', line)
    if not m_line:
      continue

    header = m_line.group(1)
    content = m_line.group(2)

    process_id, process_name = get_process_id_and_name(header)
    if process_id != last_process_id:
      filtered_output += '--------- %s (%d):\n' % (process_name, process_id)
      last_process_id = process_id

    result = (
        convert_android_crash_stack_line(content) or
        convert_chrome_crash_stack_line(content) or
        content)
    filtered_output += result + '\n'

  return filtered_output


def fix_lib_path(content, search_paths, lib_tmp_dir_path):
  """Fix lib path in stacktrace. lib_tmp_dir_path is for pulling the lib from
    the device."""
  lines = []
  for line in content.splitlines():
    match = re.match(r'\s*#([0-9]+)\s+([^\s]+)\s+\(([^+]+)\+([^)]+)\)', line)
    if not match:
      lines.append(line)
      continue

    frame_no = match.group(1)
    frame_address = match.group(2)
    binary_path = match.group(3)
    binary_address = match.group(4)

    binary_path = find_lib_path(binary_path, search_paths, lib_tmp_dir_path)
    lines.append(
        '    #%s %s (%s+%s)' %
        (frame_no, frame_address, binary_path, binary_address))

  return '\n'.join(lines)


def find_lib_path(binary_path, search_paths, lib_tmp_dir_path):
  """Find the filename in search paths (or pull from the device) and return
    full path."""
  filename = os.path.basename(binary_path)
  if not os.path.splitext(filename)[1] == ANDROID_LIBRARY_EXTENSION:
    # Skip non-library paths.
    return '<unknown>'

  for path in search_paths + [lib_tmp_dir_path]:
    full_path = os.path.join(path, filename)
    if os.path.exists(full_path):
      return full_path

  adb('pull %s %s' % (binary_path, lib_tmp_dir_path))

  full_path = os.path.join(lib_tmp_dir_path, filename)
  if not os.path.exists(full_path):
    raise Exception(
        "%s doesn't exist even after pulling from the device" % full_path)

  return full_path


def ensure_active():
  """Wake up the android device. This is needed for running Chrome."""
  _, output = adb_shell(
      'dumpsys window', print_command=False, print_output=False)
  # The device is already unlocked.
  if SCREEN_LOCK_SEARCH_STRING not in output:
    # Turn the device off.
    adb_shell(
        'input keyevent KEYCODE_POWER', print_command=False, print_output=False)
    time.sleep(1)

  # Turn it on and off to make it more reliable.
  adb_shell(
      'input keyevent KEYCODE_POWER', print_command=False, print_output=False)
  adb_shell(
      'input keyevent KEYCODE_POWER', print_command=False, print_output=False)

  # Unlock.
  adb_shell(
      'input keyevent KEYCODE_MENU', print_command=False, print_output=False)
  time.sleep(1)


def set_content_setting(table, key, value):
  """Set content with key and value."""
  adb_shell(
      ('content insert --uri content://%s --bind name:s:%s --bind '
       'value:%s' % (table, key, value)),
      print_command=False,
      print_output=False)


def reboot():
  """Reboot and waits for device."""
  adb('reboot')
  wait_until_fully_booted()


def wait_until_fully_booted():
  """Waits until fully booted."""

  def boot_completed():
    """Tests if boot_completed property is set."""
    expected = '1'
    _, result = adb_shell('getprop sys.boot_completed',
                          exit_on_error=False,
                          print_command=False,
                          print_output=False)
    return result.strip() == expected

  def drive_ready():
    """Tests if drive is ready to use."""
    expected = '0'
    _, result = adb_shell('test -d \'/\'; echo $?',
                          exit_on_error=False,
                          print_command=False,
                          print_output=False)
    return result.strip() == expected

  def package_manager_ready():
    """Tests if package manager is ready to use."""
    expected = 'package:/system/framework/framework-res.apk'
    _, result = adb_shell('pm path android',
                          exit_on_error=False,
                          print_command=False,
                          print_output=False)
    if not result:
      return False

    # Ignore any extra messages before or after the result we want.
    return expected in result.splitlines()

  adb('wait-for-device')

  start_time = time.time()
  is_boot_completed = False
  is_drive_ready = False
  is_package_manager_ready = False
  while (time.time() - start_time) < BOOT_TIMEOUT:
    is_drive_ready = is_drive_ready or drive_ready()
    is_package_manager_ready = (is_package_manager_ready or
                                package_manager_ready())
    is_boot_completed = is_boot_completed or boot_completed()
    if (is_drive_ready and
        is_package_manager_ready and
        is_boot_completed):
      return True

    time.sleep(BOOT_WAIT_INTERVAL)

  raise error.BootFailed()


def ensure_root_and_remount():
  """Ensure adb runs as root."""
  adb('root')
  _, output = adb('remount')

  if DM_VERITY_ENABLED_STRING in output:
    adb('disable-verity')
    reboot()

    adb('root')
    adb('remount')


def reset(package_name):
  """Reset the state of android."""
  adb_shell('pm clear %s' % package_name)
  adb_shell(
      'pm grant %s android.permission.READ_EXTERNAL_STORAGE' % package_name,
      print_command=False, print_output=False)
  adb_shell(
      'pm grant %s android.permission.WRITE_EXTERNAL_STORAGE' % package_name,
      print_command=False, print_output=False)
  set_content_setting(
      'com.google.settings/partner', 'use_location_for_services', 'i:0')
  set_content_setting('settings/global', 'assisted_gps_enabled', 'i:0')
  set_content_setting('settings/global', 'development_settings_enabled', 'i:0')
  set_content_setting('settings/global', 'stay_on_while_plugged_in', 'i:3')
  set_content_setting('settings/global', 'send_action_app_error', 'i:0')
  set_content_setting('settings/global', 'verifier_verify_adb_installs', 'i:0')
  set_content_setting('settings/global', 'wifi_scan_always_enabled', 'i:0')
  set_content_setting('settings/secure', 'anr_show_background', 'i:0')
  set_content_setting('settings/secure', 'doze_enabled', 'i:0')
  set_content_setting('settings/secure', 'location_providers_allowed', 's:')
  set_content_setting('settings/secure', 'lockscreen.disabled', 'i:1')
  set_content_setting('settings/secure', 'screensaver_enabled', 'i:0')
  set_content_setting('settings/system', 'accelerometer_rotation', 'i:0')
  set_content_setting('settings/system', 'auto_time', 'i:0')
  set_content_setting('settings/system', 'auto_timezone', 'i:0')
  set_content_setting('settings/system', 'lockscreen.disabled', 'i:1')
  set_content_setting('settings/system', 'notification_light_pulse', 'i:0')
  set_content_setting('settings/system', 'screen_brightness_mode', 'i:0')
  set_content_setting('settings/system', 'screen_brightness', 'i:255')
  set_content_setting('settings/system', 'user_rotation', 'i:0')


def clear_log():
  """Clears log."""
  adb('logcat -c')


def get_log():
  """Get logs."""
  _, output = adb(
      'logcat -d -v brief *:I',
      redirect_stderr_to_stdout=True,
      stdout_transformer=output_transformer.Identity())
  return output


def kill(package_name):
  """Kills the process with the package name."""
  adb_shell('am force-stop %s' % package_name, exit_on_error=False)

  # Click OK to close 'Unfortunately, Chrome has stopped'.
  # FIXME(tanin): find another way.
  ensure_active()
  adb_shell('input keyevent 66', print_command=False, print_output=False)
