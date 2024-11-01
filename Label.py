from Source import *
from Sanitizer import *
from copy import deepcopy

DEBUG = False

class Label:
    def __init__(self):
        self.label_data = []

    def add_source(self, source):
        # Check for existing source using __eq__ comparison
        if not any(source.__eq__(existing_source) for existing_source, _ in self.label_data):
            self.label_data.append((source, []))

    def add_sanitizer(self, source, sanitizer):
        # Ensure the source is in the label data
        self.add_source(source)
        # Add sanitizer if it's not already associated with the source
        for existing_source, sanitizers in self.label_data:
            if source == existing_source:
                if sanitizer not in sanitizers:
                    sanitizers.append(sanitizer)
                break

    def get_sources(self):
        return [source for source, _ in self.label_data]

    def get_sanitizers(self, source):
        for existing_source, sanitizers in self.label_data:
            if source.__eq__(existing_source):
                return sanitizers

    def combine(self, other):
        combined_label = Label()
        for source, sanitizers in self.label_data:
            combined_label.add_source(source)
            for sanitizer in sanitizers:
                combined_label.add_sanitizer(source, sanitizer)

        for other_source, other_sanitizers in other.label_data:
            for other_sanitizer in other_sanitizers:
                combined_label.add_sanitizer(other_source, other_sanitizer)

        return combined_label

    def __eq__(self, other):
        if not isinstance(other, Label):
            return NotImplemented

        if len(self.label_data) != len(other.label_data):
            return False

        for source, sanitizers in self.label_data:
            for other_source, other_sanitizers in other.label_data:
                if source == other_source and sanitizers == other_sanitizers:
                    continue
                return False

        return True

    def print_label(self):
        output = []
        for source, sanitizers in self.label_data:
            sanitizer_lines = [sanitizer.get_line() for sanitizer in sanitizers]
            output.append((source.get_source_name(), sanitizer_lines))
        print(output)

    def print_sanitizers(self, source):
        output = ""
        if self.get_sanitizers(source) != []:
            for sanitizer in self.get_sanitizers(source):
                output += sanitizer.print_sanitizer() + ", "
        return "[" + output[:-2] + "]"

    def deep_copy(self):
        # Create a new Label instance
        new_label = Label()
        # Use copy.deepcopy to ensure a deep copy of the label_data dictionary
        new_label.label_data = deepcopy(self.label_data)
        return new_label
