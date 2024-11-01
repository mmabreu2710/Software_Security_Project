from copy import deepcopy
from Multilabel import *
from Label import *
from Pattern import *

class Multilabelling:
    def __init__(self):
        # Initialize an empty dictionary to store variable names and multilabels
        self.var_to_multilabels = {}
    def get_var_to_multilabels(self):
        return self.var_to_multilabels
    def add_information(self, var, multilabel):
        if var in self.var_to_multilabels:
            # Combine existing MultiLabel with the new one
            existing_multilabel = self.var_to_multilabels[var]
            combined_multilabel = existing_multilabel.combine(multilabel)
            self.var_to_multilabels[var] = combined_multilabel
        else:
            # Add new variable with its MultiLabel
            self.var_to_multilabels[var] = multilabel

    def assign_label(self, variable_name, multilabel):
        # Mutator: Assign or update the multilabel for a given variable name
        self.var_to_multilabels[variable_name] = multilabel

    def get_multilabel(self, variable_name):
        # Selector: Return the multilabel assigned to a given variable name
        return self.var_to_multilabels.get(variable_name, None)

    def var_from_multilabel(self, multilabel):
        for var, value in self.var_to_multilabels.items():
            if multilabel == value:
                return var
        return None

    def return_all_sources_for_pattern_in_var(self, var, pattern):
        tmpSources = []
        if var in self.get_var_to_multilabels():
            tmpMultilabel = self.get_var_to_multilabels()[var]
            tmpMultilabel = self.get_var_to_multilabels()[var]
            if tmpMultilabel != None:
                tmpLabels1 = tmpMultilabel.get_labels_for_pattern_by_pattern_vuln(pattern)
                if tmpLabels1 != None:
                    for tmpLabel1 in tmpLabels1:
                        for source in tmpLabel1.get_sources():
                            tmpSources.append(source)
                    return tmpSources
        return []

    def deep_copy(self):
        # Create a new Multilabelling instance
        new_multilabelling = Multilabelling()
        # Use copy.deepcopy to ensure a deep copy of the var_to_multilabels dictionary
        new_multilabelling.var_to_multilabels = deepcopy(self.var_to_multilabels)
        return new_multilabelling

    def combine(self, other):
        # Create a new Multilabelling instance
        combined_multilabelling = Multilabelling()

        # Get all unique variable names from both multilabellings
        all_variables = set(self.var_to_multilabels.keys()).union(other.var_to_multilabels.keys())

        for variable in all_variables:
            # Initialize a new MultiLabel for the combined label
            combined_label = MultiLabel()

            # If the variable exists in the first Multilabelling, add its label
            if variable in self.var_to_multilabels:
                for label in self.var_to_multilabels[variable].patterns_to_labels.values():
                    combined_label.add_label_to_pattern(label)

            # If the variable exists in the other Multilabelling, add its label
            if variable in other.var_to_multilabels:
                for label in other.var_to_multilabels[variable].patterns_to_labels.values():
                    combined_label.add_label_to_pattern(label)

            # Assign the combined label to the variable in the new Multilabelling
            combined_multilabelling.assign_label(variable, combined_label)

        return combined_multilabelling

    def print_contents(self):
        output = {}
        for var, multilabel in self.var_to_multilabels.items():
            pattern_labels = {}
            for pattern, labels in multilabel.patterns_to_labels.items():
                vulnerability_name = pattern.get_vulnerability()
                label_list = []
                for label in labels:
                    for source in label.get_sources():
                        label_list.append((source.get_source_name(), label.print_sanitizers(source)))  # Assuming no sanitizers are to be printed
                pattern_labels[vulnerability_name] = label_list
            output[var] = pattern_labels
        print(output)
