from Multilabel import *

DEBUG = False
YES = 'yes"'
NO = 'no"'

class Vulnerabilities:
    def __init__(self):
        # Initialize an empty dictionary to store vulnerabilities organized by name
        self.vulnerabilities_dict = {}
        self.sinks_dict = {}
        self.unsanitized_dict = {}
        self.vulns_number = {}

    def report_vulnerability_hack(self, vulnerability_name, multilabel, sink):
        if DEBUG: print("I want to report" + str(vulnerability_name) + " " + str(multilabel.get_labels_for_pattern_by_pattern_vuln(vulnerability_name)) + "with sink: " + str(sink.get_sink_name()))
        for pattern, labels in multilabel.patterns_to_labels.items():
            for label in labels:
                multilabel_new = MultiLabel()
                for p in multilabel.get_patterns(): multilabel_new.add_pattern(p)
                multilabel_new.add_label_to_pattern(pattern, label.deep_copy())
                self.report_vulnerability(vulnerability_name, multilabel_new, sink)


    def report_vulnerability(self, vulnerability_name, multilabel, sink):
        """
        Save information about a detected illegal flow in a format that enables reporting.
        Args:
            vulnerability_name (str): Name of the vulnerability.
            multilabel (MultiLabel): Multilabel containing sources and sanitizers for the detected illegal flow.
        """
        #if DEBUG: print("I want to normally report" + str(vulnerability_name) + " " + str(multilabel.get_labels_for_pattern_by_pattern_vuln(vulnerability_name)) + " with sink: " + str(sink.get_sink_name()))
        #should we add this new vulnerability?
        if DEBUG: print("HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
        if self.check_previous_vuln(vulnerability_name, multilabel, sink):

            if vulnerability_name not in self.vulns_number:
                self.vulns_number[vulnerability_name] = 1
                if DEBUG: print("created first vuln" + " " + str(vulnerability_name))
            else:
                self.vulns_number[vulnerability_name] += 1
                if DEBUG: print("this is the " + str(self.vulns_number[vulnerability_name]) +  "vuln")
            # Save the information in the format of (vulnerability_name -> multilabel)

            self.vulnerabilities_dict[str(vulnerability_name) + "_" + str(self.vulns_number[vulnerability_name])] = multilabel

            # Save the information in the format of (vulnerability_name -> Sink)
            self.sinks_dict[str(vulnerability_name) + "_" + str(self.vulns_number[vulnerability_name])] = sink

            # Save the information in the format of (vulnerability_name -> string (unsanitized_flow?))
            self.unsanitized_dict[str(vulnerability_name) + "_" + str(self.vulns_number[vulnerability_name])] = YES if self.is_unsanitized(vulnerability_name, multilabel) else NO



    def get_all_vulnerabilities(self):
        """
        Get all collected vulnerabilities.
        Returns:
            dict: Dictionary containing vulnerabilities organized by name.
        """
        return self.vulnerabilities_dict


    def check_previous_vuln(self, pattern_name, multilabel, sink):
        #get source and sink we are trying to insert
        our_source_labels = multilabel.get_labels_for_pattern(multilabel.get_pattern_by_vulnerability(pattern_name))

        if not our_source_labels:
            return False

        sources = our_source_labels[0].get_sources()
        if DEBUG : print("" + str(our_source_labels[0].get_sources()))
        ourSourceName = sources[0].get_source_name()
        if DEBUG : print("ourSourceName: " + str(sources[0].get_source_name()))
        ourSourceLine = sources[0].get_line()
        if DEBUG : print("ourSourceLine: " + str(sources[0].get_line()))
        our_sink = sink
        if DEBUG : print("ourSinkName: " + str(our_sink.get_sink_name()))
        if DEBUG : print("ourSinkLine: " + str(our_sink.get_line()))

        filtered_vuln_dict = self.filter_dict_by_pattern(pattern_name)
        if DEBUG: print("filtered_dict " + str(filtered_vuln_dict))

        for vulnName, value in filtered_vuln_dict.items():
            if DEBUG: print("vulnName" + str(vulnName) + "value" + str(value))

            pattern = value.get_pattern_by_vulnerability(pattern_name)
            labels = value.get_labels_for_pattern_by_pattern_vuln(pattern)

            if not labels:
                continue

            potential_same_source = labels[0].get_sources()[0]

            labels = multilabel.get_labels_for_pattern(multilabel.get_pattern_by_vulnerability(pattern_name))
            for label in labels:
                if DEBUG: label.print_label()
                for source in label.get_sources():
                    if DEBUG : print("the sanitizers" + str(label.print_sanitizers(source)))


            if DEBUG: print("our current source Line" + str(ourSourceLine) + str(potential_same_source.get_line()) + "our current source Name" + str(ourSourceName) + str(potential_same_source.get_source_name()))
            if (ourSourceLine == potential_same_source.get_line()) and (ourSourceName) == potential_same_source.get_source_name():
                if DEBUG: print("same_source")

                potential_same_sink = self.sinks_dict[vulnName]
                if DEBUG: print( "our current sink Line" + str(our_sink.get_line()) + str(potential_same_sink.get_line()) + "our current sink Name"  + str(our_sink.get_sink_name()) + str(potential_same_sink.get_sink_name()))
                if (our_sink.get_line() == potential_same_sink.get_line()) and (our_sink.get_sink_name() == potential_same_sink.get_sink_name()):
                    if DEBUG: print("same_sink! SAO IGUAIS!")
                    #se a lista de sanitizers do que esta a tentar inserir for vazia
                    if DEBUG : print("lista de sanitizers do que esta a tentar inserir e vazia? : " + str(self.is_unsanitized(pattern_name, multilabel)))
                    if DEBUG : print("lista de sanitizers que ja la estava e vazia? : " + str(self.is_unsanitized(pattern_name, value)))


                    if self.is_unsanitized(pattern_name, multilabel):
                        self.unsanitized_dict[vulnName] = YES
                    # queremos inserir coisas mas a anterior estava vazia
                    elif self.is_unsanitized(pattern_name, value):
                        self.unsanitized_dict[vulnName] = YES
                    # queremos inserir coisas mas a anterior estava cheia
                    else:
                        pass # self.unsanitized_dict[vulnName] = YES
                        #join dos sanitizers
                        #print(sanitizers_to_add = our_source_labels[0].get_sanitizers())
                        #sanitizers_to_add = our_source_labels[0].get_sanitizers()
                        #labels[0].get_sanitizers

                    return False
        return True


    def is_unsanitized(self, pattern_name, multilabel):
        labels = multilabel.get_labels_for_pattern(multilabel.get_pattern_by_vulnerability(pattern_name))
        for label in labels:
            if DEBUG: label.print_label()
            for source in label.get_sources():
                if DEBUG: label.print_sanitizers(source)
                if label.get_sanitizers(source) == []:
                    return True
        return False


    def filter_dict_by_pattern(self,substring):
        filtered_dict = {key: value for key, value in self.vulnerabilities_dict.items() if substring in key}
        return filtered_dict


    def printVulnerabilities(self):
        if DEBUG: print(self.vulnerabilities_dict)
        output = "["
        for vulnerability_name, multilabel in self.vulnerabilities_dict.items():
            if vulnerability_name not in self.unsanitized_dict:
                pass

            pattern_vuln_name = vulnerability_name[:-2]
            pattern = multilabel.get_pattern_by_vulnerability(pattern_vuln_name)

            labels = multilabel.get_labels_for_pattern_by_pattern_vuln(pattern)
            for label in labels:
                sources = label.get_sources()


                for source in sources:
                    output += '{"vulnerability": "'
                    output += str(vulnerability_name)
                    output += '", '
                    output += '"source": '
                    sourceName = source.get_source_name()
                    sourceLine = source.get_line()
                    sanitizers = label.get_sanitizers(source)
                    output += '["' + sourceName + '", ' + str(sourceLine) + "], "

                    sink = self.sinks_dict[vulnerability_name]
                    sinkName = sink.get_sink_name()
                    sinkLine = sink.get_line()
                    output += '"sink": '
                    output += '["' + sinkName  + '", ' +  str(sinkLine) + "], "

                    output += '"unsanitized_flows": "' + self.unsanitized_dict[vulnerability_name] + ", "
                    output += '"sanitized_flows": ['

                    if sanitizers != []:
                        output += label.print_sanitizers(source)

                    output += ']}, '

        output = output[:-2]
        output += "]"
        print(output)
        return output
