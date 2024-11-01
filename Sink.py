class Sink:
    def __init__(self, line, sink_name):
        self._line = line
        self._sink_name = sink_name

    # Getter for line
    def get_line(self):
        return self._line

    # Setter for line
    def set_line(self, line):
        self._line = line

    # Getter for sink_name
    def get_sink_name(self):
        return self._sink_name

    # Setter for sink_name
    def set_sink_name(self, sink_name):
        self._sink_name = sink_name
    
    def __eq__(self, other):
        if not isinstance(other, Sink):
            return NotImplemented
        return self._line == other._line and self._sink_name == other._sink_name

