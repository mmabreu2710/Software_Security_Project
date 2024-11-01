class Sanitizer:
    def __init__(self, line, sanitizer_name):
        self._line = line
        self._sanitizer_name = sanitizer_name

    # Getter for line
    def get_line(self):
        return self._line

    # Setter for line
    def set_line(self, line):
        self._line = line

    # Getter for sanitizer_name
    def get_sanitizer_name(self):
        return self._sanitizer_name

    # Setter for sanitizer_name
    def set_sanitizer_name(self, sanitizer_name):
        self._sanitizer_name = sanitizer_name

    def __eq__(self, other):
        if not isinstance(other, Sanitizer):
            return NotImplemented
        return self._line == other._line and self._sanitizer_name == other._sanitizer_name
    def print_sanitizer(self):
        return '["' + self.get_sanitizer_name() + '", ' + str(self.get_line()) + "]"

