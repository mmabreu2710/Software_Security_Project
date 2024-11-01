class Pattern:
    def __init__(self, vulnerability, sources, sanitizers, sinks, implicit):
        self.vulnerability = vulnerability
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit = implicit

    def get_vulnerability(self):
        return self.vulnerability

    def get_sources(self):
        return self.sources

    def get_sanitizers(self):
        return self.sanitizers

    def get_sinks(self):
        return self.sinks

    def get_implicit(self):
        return self.implicit

    def is_vulnerability(self, vulnerability):
        return vulnerability in self.vulnerability

    def is_source(self, source):
        return source in self.sources

    def is_sink(self, sink):
        return sink in self.sinks

    def is_sanitizer(self, sanitizer):
        return sanitizer in self.sanitizers

    def is_implicit(self, implicit):
        return implicit in self.implicit

    def print_pattern(self):
        return {
            "vulnerability": self.vulnerability,
            "sources": self.sources,
            "sanitizers": self.sanitizers,
            "sinks": self.sinks,
            "implicit": self.implicit
        }

    def __eq__(self, other):
        if not isinstance(other, Pattern):
            return NotImplemented
        return self.vulnerability == other.vulnerability and self.sources == other.sources and self.sanitizers == other.sanitizers and self.sinks == other.sinks and self.implicit == other.implicit

    def __hash__(self) -> int:
        return 1
