from Pattern import *
from Label import *
from Sanitizer import *
from Sink import *
from Source import *
from copy import deepcopy

class MultiLabel:
    def __init__(self):
        # Dictionary to store a list of Label objects for each Pattern object
        self.patterns_to_labels = {}

    def add_pattern(self, pattern):
        """Add a new pattern with an empty list of labels."""
        if pattern not in self.patterns_to_labels:
            self.patterns_to_labels[pattern] = []

    def add_label_to_pattern(self, pattern, label): #temos de comfirmar que a as sources e sanitizer da label fazem parte do pattern
        """Add a label to a specific pattern."""
        #if (pattern.get_sources() in and pattern.get_sanitizers() in self.patterns_to_labels[pattern]) or (pattern.get_sources() in self.patterns_to_labels[pattern]):
        for source in label.get_sources():
            if source._source_name not in pattern.get_sources():
                pass #ok maybe

            for sanitizer in label.get_sanitizers(source):
                if sanitizer._sanitizer_name not in pattern.get_sanitizers():
                    return

        self.patterns_to_labels[pattern].append(label)


    def get_patterns(self):
        """Retrieves all patterns"""
        return list(self.patterns_to_labels.keys())
    def get_list_of_pattern_strings(self):
        patterList = []
        for tmppattern in self.get_patterns():
            patterList.append(tmppattern.get_vulnerability())
        return patterList

    def get_labels_for_pattern(self, pattern):
        """Retrieve labels for a specific pattern."""
        return self.patterns_to_labels[pattern]

    def get_labels_for_pattern_by_pattern_vuln(self, pattern):
        """Retrieve labels for a specific pattern."""
        return self.patterns_to_labels.get(pattern, [])

    def combine(self, other):
        combined_multilabel = MultiLabel()

        for pattern in set(self.patterns_to_labels.keys()).union(set(other.patterns_to_labels.keys())):
            combined_multilabel.add_pattern(pattern)

            # Get labels from self for this pattern
            self_labels = self.patterns_to_labels.get(pattern, [])
            # Get labels from other for this pattern
            other_labels = other.patterns_to_labels.get(pattern, [])

            # Use the __eq__ method from Label class for comparison
            for label in self_labels:
                if label not in combined_multilabel.patterns_to_labels[pattern]:
                    combined_multilabel.add_label_to_pattern(pattern, label)

            for label in other_labels:
                if label not in combined_multilabel.patterns_to_labels[pattern]:
                    combined_multilabel.add_label_to_pattern(pattern, label)

        return combined_multilabel

    def __eq__(self, other):
        if not isinstance(other, MultiLabel):
            return NotImplemented

        # Check if both have the same set of patterns
        if set(self.patterns_to_labels.keys()) != set(other.patterns_to_labels.keys()):
            return False

        # For each pattern, check if the associated labels are the same
        for pattern, labels in self.patterns_to_labels.items():
            other_labels = other.patterns_to_labels.get(pattern, [])
            if len(labels) != len(other_labels):
                return False

            # Check each label in the list for equality
            for label in labels:
                if label not in other_labels:
                    return False

        return True

    def equals_except_sanitizers(self, other):
        if not isinstance(other, MultiLabel):
            return NotImplemented

        # Check if both have the same set of patterns
        if set(self.patterns_to_labels.keys()) != set(other.patterns_to_labels.keys()):
            return False

        # For each pattern, check if the associated labels are the same
        for pattern, labels in self.patterns_to_labels.items():
            other_labels = other.patterns_to_labels.get(pattern, [])
            if len(labels) != len(other_labels):
                return False

            # Check each label in the list for equality
            for label in labels:
                if label not in other_labels:
                    return False

        return True

    def get_pattern_by_vulnerability(self, vulnerability_name):
        """Retrieve a pattern object based on its vulnerability name."""
        for pattern in self.patterns_to_labels:
            if pattern.get_vulnerability() == vulnerability_name:
                return pattern
        return None  # Return None if no matching pattern is found

    def print_contents(self):
        output = {}
        for pattern, labels in self.patterns_to_labels.items():
            vulnerability_name = pattern.get_vulnerability()
            label_list = []
            for label in labels:
                for source in label.get_sources():
                    # Append each source individually as a tuple
                    label_list.append((source.get_source_name(), []))  # Assuming no sanitizers are to be printed do this function to print sanitizers
            output[vulnerability_name] = label_list
        print(output)
    def get_label_for_pattern_and_line(self, pattern, line):
        for label in self.patterns_to_labels[pattern]:
            for source in label.get_sources():
                if source.get_line() == line:
                    return label

    def deep_copy(self):
        # Create a new MultiLabel instance
        new_multilabel = MultiLabel()
        # Use copy.deepcopy to ensure a deep copy of the patterns_to_labels dictionary
        for pattern in self.patterns_to_labels:
            new_multilabel.patterns_to_labels[pattern] = deepcopy(self.patterns_to_labels[pattern])
        return new_multilabel
