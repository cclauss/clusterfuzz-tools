"""Transform the output before printing on screen."""

try:
  xrange
except NameError:
  xrange = range


class Base(object):
  """Transform output and send to the output function."""

  def set_output(self, output):
    """Set output."""
    self.output = output

  def write(self, s):
    """Write string to output."""
    self.output.write(s)
    self.output.flush()

  def process(self, string):
    """Process string and send to output_fn."""
    raise NotImplementedError

  def flush(self):
    """Send the residue to output_fn."""
    raise NotImplementedError


class Hidden(Base):
  """Hide output and print dot every N characters."""

  def __init__(self, n=100):
    self.n = n
    self.count = 0

  def process(self, string):
    """Process string and send to output_fn."""
    all_count = self.count + len(string)

    if all_count < self.n:
      self.count = all_count
      return

    for _ in xrange(int(all_count / self.n)):
      self.write('.')

    self.count = all_count % self.n

  def flush(self):
    """Send the residue to output_fn."""
    self.write('.\n')


class Identity(Base):
  """Print output as it comes."""

  def process(self, string):
    """Process string and send to output_fn."""
    self.write(string)

  def flush(self):
    """Send the residue to output_fn."""
    self.write('')


def contains_failure(lines):
  """Check if any line starts with 'FAILED'."""
  for line in lines:
    if line.startswith('FAILED'):
      return True
  return False


class Ninja(Base):
  """Process ninja output and correctly replace previous lines."""

  def __init__(self):
    self.current_line = ''
    self.previous_line_size = 0
    self.previous_failed = False
    self.lines = []

  def process(self, string):
    """Parse raw string into lines."""
    if '\n' not in string:
      self.current_line += string
      return

    tokens = string.split('\n')
    self.current_line += tokens[0]
    self.process_line(self.current_line)
    self.current_line = tokens[-1]

    for line in tokens[1:-1]:
      self.process_line(line)

  def process_line(self, line):
    """Process each line individually."""
    if not line.startswith('['):
      self.lines.append(line)
      return

    self.print_block(self.lines)
    self.lines = [line]

  def print_block(self, lines):
    """Print the whole block."""
    if contains_failure(lines):
      for line in lines:
        self.print_line(line)
        self.write('\n')
        self.previous_failed = True
    else:
      for line in lines:
        self.print_line(line)
        self.previous_failed = False

  def print_line(self, line):
    """Print a single line."""
    line_size = len(line)

    if not self.previous_failed:
      if line_size < self.previous_line_size:
        line += ' ' * (self.previous_line_size - line_size)
      self.write('\b' * self.previous_line_size)

    self.write(line)

    self.previous_line_size = len(line)

  def flush(self):
    """Print the residue output."""
    self.print_block(self.lines)
    self.write('\n')
