class Source:
    def __init__(self, line, source_name):
        self._line = line
        self._source_name = source_name

    # Getter for line
    def get_line(self):
        return self._line

    # Setter for line
    def set_line(self, line):
        self._line = line

    # Getter for source_name
    def get_source_name(self):
        return self._source_name

    # Setter for source_name
    def set_source_name(self, source_name):
        self._source_name = source_name

    def __eq__(self, other):
        if not isinstance(other, Source):
            return NotImplemented
        return self._line == other._line and self._source_name == other._source_name

