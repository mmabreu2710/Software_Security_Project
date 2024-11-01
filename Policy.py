from Vulnerabilities import *
from Multilabel import *
from Label import *
from Pattern import *

class Policy:
    def __init__(self, patterns):
        self.patterns = patterns

    def get_patterns(self):
        return self.patterns

    def get_vulnerability_names(self):
        return [pattern.get_vulnerability() for pattern in self.patterns]
    
    def find_string_in_sources(self, search_string):
        indices = [index for index, pattern in enumerate(self.patterns) if search_string in pattern.get_sources()]
        return indices if indices else None

    '''given a source return the vulnerability name'''
    def sources_for_name(self, source):
        string_indices = self.find_string_in_sources(source)
        if string_indices is not None:
            vulnerability_names = self.get_vulnerability_names()
            return [vulnerability_names[index] for index in string_indices]
        else:
            return None
        
    def find_string_in_sanitizers(self, search_string):
        indices = [index for index, pattern in enumerate(self.patterns) if search_string in pattern.get_sanitizers()]
        return indices if indices else None
    
    def sanitizers_for_name(self, sanitizer):
        string_indices = self.find_string_in_sanitizers(sanitizer)
        if string_indices is not None:
            vulnerability_names = self.get_vulnerability_names()
            return [vulnerability_names[index] for index in string_indices]
        else:
            return None
        
    def find_string_in_sinks(self, search_string):
        indices = [index for index, pattern in enumerate(self.patterns) if search_string in pattern.get_sinks()]
        return indices if indices else None

    def sinks_for_name(self, sink):
        string_indices = self.find_string_in_sinks(sink)
        if string_indices is not None:
            vulnerability_names = self.get_vulnerability_names()
            return [vulnerability_names[index] for index in string_indices]
        else:
            return None


    def calculate_index_for_vulnerability(self, name):
        vulnerability_names = self.get_vulnerability_names()
        try:
            index = vulnerability_names.index(name)
            return index
        except ValueError:
            return None

    '''given a vulnerability returns all sources for that vulnerability'''

    def all_sources_for_name(self, name):
        all_sources = [pattern.get_sources() for pattern in self.patterns]
        index = self.calculate_index_for_vulnerability(name)
        return all_sources[index]

    def all_sanitizers_for_name(self, name):
        all_sanitizers = [pattern.get_sanitizers() for pattern in self.patterns]
        index = self.calculate_index_for_vulnerability(name)
        return all_sanitizers[index]

    def all_sinks_for_name(self, name):
        all_sinks = [pattern.get_sinks() for pattern in self.patterns]
        index = self.calculate_index_for_vulnerability(name)
        return all_sinks[index]

    def is_the_name_implicit(self,name):
        implicit = [pattern.get_implicit() for pattern in self.patterns]
        index = self.calculate_index_for_vulnerability(name)
        return implicit[index]
    
    def illegal_flows(self, name, multilabel):
        illegal_flows_vulnerabilities = Vulnerabilities()

        for pattern in self.patterns:
            illegal_flows_for_pattern = []
            for label in multilabel.get_labels_for_pattern(pattern):
                if label.has_sink(name):
                    illegal_flows_for_pattern.append(label)

            if illegal_flows_for_pattern:
                illegal_flows_vulnerabilities.add_pattern(pattern)
                for illegal_label in illegal_flows_for_pattern:
                    illegal_flows_vulnerabilities.add_label_to_pattern(pattern, illegal_label)

        return illegal_flows_vulnerabilities

