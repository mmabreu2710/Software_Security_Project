import sys
from auxiliary import *
import ast
import astexport.export
import json
from Pattern import *
from Policy import *
from Source import *
from Sanitizer import *
from Label import *
from Multilabel import *
from Vulnerabilities import *
from Multilabelling import *


#recursive function to traverse the ast tree and print ast_type.
DEBUG = False
vars = {}  # list of vars
Sources = []
Sinks = []
actualSinks = []
vulnerabilities = []
centralMultilabelling = Multilabelling()
vuln = Vulnerabilities()

import pprint
pp = pprint.PrettyPrinter()

GLOBAL_TOOL_POLICY = None

def traverse_ast(ast_node, as_name=False):
    if isinstance(ast_node, dict):
        node_type = ast_node.get('ast_type')
        line_number = ast_node.get('lineno', 'N/A')

        # Print node type and line number for current node
        if node_type:
            if DEBUG: print(f"Node Type: {node_type}, Starting Line: {line_number}")

        if node_type == 'Constant':
            if DEBUG: print("Constant Node found!")
            multilabel = MultiLabel()
            for pattern in GLOBAL_TOOL_POLICY.get_patterns(): multilabel.add_pattern(pattern)
            return multilabel

        elif node_type == 'Name':
            if DEBUG: print("Name Node found!")
            if ast_node["ctx"]["ast_type"] == "Store" or as_name:
                return ast_node["id"]
            elif ast_node["ctx"]["ast_type"] == "Load":
                multilabel = centralMultilabelling.get_multilabel(ast_node["id"])
                if multilabel is None:
                    multilabel = MultiLabel()

                    for pattern in GLOBAL_TOOL_POLICY.get_patterns():
                        label = Label()
                        multilabel.add_pattern(pattern)
                        for source in pattern.get_sources():
                            label.add_source(Source(line_number, ast_node["id"]))
                        multilabel.add_label_to_pattern(pattern, label)

                    return multilabel

                for pattern in GLOBAL_TOOL_POLICY.get_patterns():
                    if pattern.is_source(ast_node["id"]):
                        label = Label()
                        label.add_source(Source(line_number, ast_node["id"]))
                        multilabel.add_label_to_pattern(pattern, label)

                return multilabel
            elif ast_node["ctx"]["ast_type"] == "Del":
                del centralMultilabelling.get_var_to_multilabels()[ast_node["id"]]
            else:
                raise NotImplementedError(ast_node["ctx"]["ast_type"])

        elif node_type == 'BinOp':
            if DEBUG: print("BinOp Node found!")
            return traverse_ast(ast_node["left"]).combine(traverse_ast(ast_node["right"]))

        elif node_type == 'UnaryOp':
            if DEBUG: print("UnaryOp Node found!")
            return traverse_ast(ast_node["value"])

        elif node_type == 'BoolOp':
            if DEBUG: print("BinOp Node found!")
            #op, values -> combine all values with the op
            result = ast_node["values"][0]
            for value in ast_node["values"][1:]:
                result = traverse_ast(result).combine(traverse_ast(value))
            return result

        elif node_type == 'Compare':
            if DEBUG: print("Compare Node found!")
            #left, ops, comparators
            result = traverse_ast(ast_node["left"])
            for comparator in ast_node["comparators"]:
                result = result.combine(traverse_ast(comparator))
            return result

        elif node_type == 'Call':
            if DEBUG: print("Call Node found!")
            if DEBUG: pp.pprint(ast_node)
            function_name = traverse_ast(ast_node["func"], as_name=True)
            arguments = [traverse_ast(arg).deep_copy() for arg in ast_node["args"]] + [traverse_ast(keyword["value"]).deep_copy() for keyword in ast_node["keywords"]]

            for argument in arguments:
                for pattern in GLOBAL_TOOL_POLICY.get_patterns():
                    argument.add_pattern(pattern)

                    labels = argument.get_labels_for_pattern(pattern)
                    if pattern.is_sink(function_name):
                        vuln.report_vulnerability_hack(pattern.get_vulnerability(), argument, Sink(line_number, function_name))
                    elif pattern.is_source(function_name):
                        for label in labels:
                            label.add_source(Source(line_number, function_name))
                    elif pattern.is_sanitizer(function_name):
                        for label in labels:
                            for source in label.get_sources():
                                label.add_sanitizer(source, Sanitizer(line_number, function_name))

            multilabel = MultiLabel()
            for pattern in GLOBAL_TOOL_POLICY.get_patterns():
                multilabel.add_pattern(pattern)

                labels = multilabel.get_labels_for_pattern(pattern)
                if pattern.is_source(function_name):
                    label = Label()
                    label.add_source(Source(line_number, function_name))
                    multilabel.add_label_to_pattern(pattern, label)

            for argument in arguments:
                multilabel = multilabel.combine(argument)

            return multilabel

        elif node_type == 'Attribute':
            if DEBUG: print("Attribute Node found!")
            if ast_node["ctx"]["ast_type"] == "Store" or as_name:
                return ast_node["attr"]
            elif ast_node["ctx"]["ast_type"] == "Load":
                return centralMultilabelling.get_multilabel(ast_node["attr"])
            elif ast_node["ctx"]["ast_type"] == "Del":
                del centralMultilabelling.get_var_to_multilabels()[centralMultilabelling.var_from_multilabel(ast_node["attr"])]
            else:
                raise NotImplementedError(ast_node["ctx"]["ast_type"])

        elif node_type == 'Expr':
            if DEBUG: print("Expr Node found!")
            return traverse_ast(ast_node["value"])


        elif node_type == 'Assign':
            if DEBUG: print("Assign Node found!")
            value = traverse_ast(ast_node["value"])
            for target in ast_node["targets"]:
                target_name = traverse_ast(target)
                centralMultilabelling.assign_label(target_name, value)

                for pattern in GLOBAL_TOOL_POLICY.get_patterns():
                    value.add_pattern(pattern)

                    if pattern.is_sink(target_name):
                        vuln.report_vulnerability_hack(pattern.get_vulnerability(), value, Sink(line_number, target_name))

            return value

        elif node_type == 'If':
            #test holds a single node (ex:Compare).
            #body and orelse each hold a list of nodes.
            if DEBUG: print("If Node found!")
            traverse_ast(ast_node["test"])
            for body_item in ast_node["body"]:
                traverse_ast(body_item)
            for orelse_item in ast_node["orelse"]:
                traverse_ast(orelse_item)

        elif node_type == 'While':
            #class ast.While(test, body, orelse)
            if DEBUG: print("While Node found!")
            traverse_ast(ast_node["test"])
            for body_item in ast_node["body"]:
                traverse_ast(body_item)
            for body_item in ast_node["body"]:
                traverse_ast(body_item)
            for body_item in ast_node["body"]:
                traverse_ast(body_item)
            for orelse_item in ast_node["orelse"]:
                traverse_ast(orelse_item)

        # Continue traversal for other node types
        else:
            for value in ast_node.values():
                if isinstance(value, (dict, list)):
                    if isinstance(value, list):
                        for item in value:
                            traverse_ast(item)
                    else:
                        traverse_ast(value)

def get_all_sources_from_labels(labels):
    sources = []
    for label in labels:
        for source in label.get_sources():
            sources.append(source)
    return list(sources)

def analyse_call_var(node):
    if node['ast_type'] == 'Assign':
            if node['targets'][0]['ast_type'] == 'Name':
                vars[node['targets'][0]['id']] = node['lineno']

def put_source_in_multilabelling(source, var, pattern, sanitizer):
    if DEBUG: print("Pattern!: " + pattern.get_vulnerability())
    if DEBUG: print("Caminho para var: " + var)
    Sources.append(source)
    tmpLabel = Label()
    tmpLabel.add_source(source) #so funciona sem sanitizers, AINDA...
    if sanitizer == None:
        tmpLabel.add_source(source)
    else:
        tmpLabel.add_sanitizer(source, sanitizer)
    tmpMultilabel = MultiLabel()
    tmpMultilabel.add_pattern(pattern)
    tmpMultilabel.add_label_to_pattern(tmpMultilabel.get_pattern_by_vulnerability(pattern.get_vulnerability()), tmpLabel)
    centralMultilabelling.add_information(var, tmpMultilabel)
    if DEBUG:print("centralMultilabelling:")
    if DEBUG:print(centralMultilabelling.print_contents())

def analyse_call_source(node, pattern, policy):
    if node['ast_type'] == 'Assign':
        if node["value"]["ast_type"] == "Call":
            if node['value']["func"]['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
                tmpSource = Source(node['lineno'], node['value']["func"]['id'])
                tmpSanitizer = None
                var = node['targets'][0]['id']
                put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

            elif node['value']["func"]['id'] in policy.all_sanitizers_for_name(pattern.get_vulnerability()):
                variables = find_name_nodes_for_bin_opp(node['value']['args'])
                if DEBUG: print(variables)
                for arg in variables:
                    if arg['ast_type'] == "Name":
                        if arg['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
                            tmpSource = Source(node['lineno'], arg['id'])
                            tmpSanitizer = Sanitizer(node['lineno']), node['value']["func"]['id']
                            var = node['targets'][0]['id']
                            put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

                        elif arg['id'] in centralMultilabelling.get_var_to_multilabels():
                            for source in centralMultilabelling.return_all_sources_for_pattern_in_var(arg['id'], pattern):
                                if DEBUG: print("Sources:")
                                if DEBUG: print(source.get_source_name())
                                if DEBUG: print(policy.all_sources_for_name(pattern.get_vulnerability()))
                                if source.get_source_name() in policy.all_sources_for_name(pattern.get_vulnerability()):
                                    if DEBUG: print("entrou")
                                    tmpSource = Source(source.get_line(), source.get_source_name())
                                    tmpSanitizer = Sanitizer(node['lineno'],node['value']["func"]['id'])
                                    var = node['targets'][0]['id']
                                    put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

            elif node['value']['args'] != None:
                for arg in node['value']['args']:
                    if 'id' in arg and arg['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
                        tmpSource = Source(node['lineno'], arg['id'])
                        tmpSanitizer = None
                        var = node['targets'][0]['id']
                        put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

            elif node["value"]["ast_type"] == "Name":
                if node['value']['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
                    tmpSource = Source(node['lineno'], node['value']['id'])
                    tmpSanitizer = None
                    var = node['targets'][0]['id']
                    put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

                elif node['value']['id'] in centralMultilabelling.get_var_to_multilabels():
                    if DEBUG: print("Caminho 3 para var: " + node['targets'][0]['id'])
                    for source in centralMultilabelling.return_all_sources_for_pattern_in_var(node['value']['id'], pattern):
                        if source.get_source_name in policy.all_sources_for_name(pattern.get_vulnerability()):
                            tmpSource = Source(node['lineno'], node['value']['id'])
                            tmpSanitizer = None
                            var = node['targets'][0]['id']
                            put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

        elif node["value"]["ast_type"] == "Name":
                if node['value']['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
                    tmpSource = Source(node['lineno'], node['value']['id'])
                    tmpSanitizer = None
                    var = node['targets'][0]['id']
                    put_source_in_multilabelling(tmpSource,var, pattern,tmpSanitizer)

                elif node['value']['id'] in centralMultilabelling.get_var_to_multilabels():
                    if DEBUG: print("Caminho para 5 var: " + node['targets'][0]['id'])
                    tmpMultilabel = centralMultilabelling.get_var_to_multilabels()[node['value']['id']]
                    tmpLabels = tmpMultilabel.get_labels_for_pattern_by_pattern_vuln(pattern)
                    for tmpLabel in tmpLabels:
                        tmpSources = tmpLabel.get_sources()
                        for source in tmpSources:
                            if source.get_source_name() in policy.all_sources_for_name(pattern.get_vulnerability()):
                                tmpMultilabel = MultiLabel()
                                tmpMultilabel.add_pattern(pattern)
                                tmpMultilabel.add_label_to_pattern(tmpMultilabel.get_pattern_by_vulnerability(pattern.get_vulnerability()), tmpLabel)
                                centralMultilabelling.add_information(node['targets'][0]['id'], tmpMultilabel)
                                if DEBUG: print("centralMultilabeling:")
                                if DEBUG: print(centralMultilabelling.print_contents())

        if node['targets'][0]['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
            tmpSource = Source(node['lineno'], node['targets'][0]['id'])
            Sources.append(tmpSource)


def analyse_call_sink(node, pattern,policy):
    if node['ast_type'] == 'Assign':
        vulnerability = analyse_subcall_sink_assign(node, policy, vars, pattern)
        vulnerabilities.append(vulnerability)

    elif node['ast_type'] == 'Expr':
        vulnerability = analyse_subcall_sink_expr(node, policy, vars, pattern)
        vulnerabilities.append(vulnerability)

def report_sink_to_vuln(sink, source, pattern, sanitizers):
    if DEBUG: print("aleluia")
    actualSinks.append(sink)
    tmpMultilabel2 = MultiLabel()
    tmpMultilabel2.add_pattern(pattern)
    tmpLabel2 = Label()
    tmpLabel2.add_source(source)
    if sanitizers != None:
        for sanitizer in sanitizers:
            tmpLabel2.add_sanitizer(source, sanitizer)
    tmpMultilabel2.add_label_to_pattern(pattern, tmpLabel2)
    if DEBUG: print("tmpMultilabel2:")
    if DEBUG: print(tmpMultilabel2.print_contents())
    vuln.report_vulnerability(pattern.get_vulnerability(), tmpMultilabel2, sink)

def analyse_subcall_sink_assign(node, policy, vars, pattern):
    if 'id' in node['targets'][0] and node['targets'][0]['id'] in policy.all_sinks_for_name(pattern.get_vulnerability()):
        tmpSink = Sink(node['lineno'], node['targets'][0]['id'])
        Sinks.append(tmpSink)
        if node['value']['ast_type'] == 'Name' and node['value']['id'] in vars:
            source_var = node['value']['id']
            sink_name = node['targets'][0]['id']
            if DEBUG: print("HEY")
            if DEBUG: print(source_var)
            # Check if the source variable originates from a source
            for source in centralMultilabelling.return_all_sources_for_pattern_in_var(source_var, pattern):
                if policy.sources_for_name(source.get_source_name()) is not None and  pattern.get_vulnerability() in policy.sources_for_name(source.get_source_name()):
                    tmpSink = Sink(node['lineno'], sink_name)
                    tmpSanitizers = None
                    report_sink_to_vuln(tmpSink,source, pattern,tmpSanitizers)

            if policy.sources_for_name(source.get_source_name()) is not None and pattern.get_vulnerability() in policy.sources_for_name(source_var):
                tmpSink = Sink(node['lineno'], sink_name)
                tmpSource= Source(node['lineno'], source_var)
                tmpSanitizers = None
                report_sink_to_vuln(tmpSink,tmpSource, pattern, tmpSanitizers)

        elif node["value"]['func']['ast_type'] == 'Name':
            func_name = node["value"]['func']['id']
            sink_name = node['targets'][0]['id']
            if policy.sources_for_name(func_name) is not None and pattern.get_vulnerability() in policy.sources_for_name(func_name):
                tmpSink = Sink(node['lineno'], sink_name)
                tmpSource= Source(node['lineno'], func_name)
                tmpSanitizers = None
                report_sink_to_vuln(tmpSink,tmpSource, pattern, tmpSanitizers)

        elif node["value"]['ast_type'] == 'Call':
            analyse_subcall_sink_expr(node, policy, vars, pattern)
    elif node["value"]['ast_type'] == 'Call':
            analyse_subcall_sink_expr(node, policy, vars, pattern)

def find_name_nodes_for_bin_opp(node):
    name_nodes = []

    def traverse2(n):
        if isinstance(n, dict):
            if n.get('ast_type') == 'Name':
                name_nodes.append(n)
            for key, value in n.items():
                traverse2(value)
        elif isinstance(n, list):
            for item in n:
                traverse2(item)

    traverse2(node)
    return name_nodes

def analyse_subcall_sink_expr_possible_binop(node, policy, vars, pattern):
    variables = find_name_nodes_for_bin_opp(node['value']['args'])
    tmpSink = Sink(node['lineno'], node['value']["func"]['id'])
    for arg in variables:
        if DEBUG: print(arg)
        if arg['ast_type'] == 'Name' and arg['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
            tmpSource = Source(arg['lineno'], arg['id'])
            tmpSanitizers = None
            report_sink_to_vuln(tmpSink,tmpSource, pattern, tmpSanitizers)

        if (arg['ast_type'] == 'Name' and arg['id'] in vars):
            source_var = arg['id']
            if DEBUG: print("Entrou com : " + arg['id'])
            if DEBUG: print(source_var)
            # Check if the source variable originates from a source
            tmpMultilabel = centralMultilabelling.get_multilabel(source_var)
            #if tmpMultilabel != None:
            for source in centralMultilabelling.return_all_sources_for_pattern_in_var(source_var, pattern):
                if source.get_source_name() in centralMultilabelling.get_var_to_multilabels():
                    for source2 in centralMultilabelling.return_all_sources_for_pattern_in_var(source.get_source_name(), pattern):
                        if policy.sources_for_name(source2.get_source_name()) != None:
                            tmpSanitizers = None
                            report_sink_to_vuln(tmpSink,source2, pattern, tmpSanitizers)

                if policy.sources_for_name(source.get_source_name()) is not None and pattern.get_vulnerability() in policy.sources_for_name(source.get_source_name()):
                    tmpSink = Sink(node['lineno'], node['value']["func"]['id'])
                    tmpSanitizers = None
                    patterList = tmpMultilabel.get_list_of_pattern_strings()
                    tmpLabelwithSanitizers = None
                    if pattern.get_vulnerability() in patterList:
                        tmpLabelwithSanitizers = tmpMultilabel.get_label_for_pattern_and_line(pattern, source.get_line())
                    if tmpLabelwithSanitizers != None:
                        tmpSanitizers = tmpLabelwithSanitizers.get_sanitizers(source)
                        if DEBUG: print(str(source.get_line()))
                        if DEBUG: print(tmpLabelwithSanitizers.print_label())
                    report_sink_to_vuln(tmpSink,source, pattern, tmpSanitizers)

        elif arg['ast_type'] == 'Name' and arg['id'] not in vars:
            tmpsinkList = []
            tmpsourceList = []
            for sink in Sinks:
                tmpsinkList.append(sink.get_sink_name())
            for sourc in Sources:
                tmpsourceList.append(sourc.get_source_name())
            if arg['id'] not in tmpsinkList and arg['id'] not in tmpsourceList:
                tmpSource = Source(arg['lineno'], arg['id'])
                tmpSanitizers = None
                report_sink_to_vuln(tmpSink,tmpSource, pattern, tmpSanitizers)

def analyse_subcall_sink_expr(node, policy, vars, pattern):
    if node["value"]["ast_type"] == "Call":
        if DEBUG: print("Sanitizers here:")
        if DEBUG: print(policy.all_sanitizers_for_name(pattern.get_vulnerability()))
        if node['value']["func"]['id'] in policy.all_sinks_for_name(pattern.get_vulnerability()):
            tmpSink = Sink(node['lineno'], node['value']["func"]['id'])
            Sinks.append(tmpSink)
            if node["value"]['func']['ast_type'] == 'Name':
                func_name = node["value"]['func']['id']
                if DEBUG: print("func:")
                if DEBUG: print(func_name)
                # Check if the function is a sink
                if DEBUG: print("Checking:")
                if policy.sinks_for_name(func_name) is not None and pattern.get_vulnerability() in policy.sinks_for_name(func_name):
                    analyse_subcall_sink_expr_possible_binop(node, policy, vars, pattern)
        '''elif node['value']["func"]['id'] in policy.all_sanitizers_for_name(pattern.get_vulnerability()):
            for arg in node['value']['args']:
                if arg["ast_type"] == "Name":
                    print("OH no")
                    print(policy.all_sources_for_name(pattern.get_vulnerability()))
                    if arg['id'] in policy.all_sources_for_name(pattern.get_vulnerability()):
                        print("YEAAAAH")'''

def traverse_and_analyze(ast_node, policy):
    visited_nodes = {}
    def traverse(node):
        analyse_call_var(node)
        for pattern in policy.get_patterns():
            visited_nodes[pattern] = []
        for pattern in policy.get_patterns():
            analyse_call_source(node, pattern, policy)
            analyse_call_sink(node, pattern,policy)
            visited_nodes[pattern].append(node)
            for value in node.values():
                if isinstance(value, list):
                    for item in value:
                        if item not in visited_nodes[pattern]:
                            traverse(item)
                elif isinstance(value, dict):
                    if value not in visited_nodes[pattern]:
                        traverse(value)

    traverse(ast_node)

    print("Multilabelling:")
    print(centralMultilabelling.print_contents())
    print("Variaveis:")
    for var in vars:
        print(var)
    print("Sinks:")
    for s in Sinks:
        print("[" +str(s.get_sink_name()) + "," + str(s.get_line()) + "]")
    print("Actual Sinks:")
    for s in actualSinks:
        print("[" +str(s.get_sink_name()) + "," + str(s.get_line()) + "]")
    print("Sources:")
    for s in Sources:
        print("[" +str(s.get_source_name()) + "," + str(s.get_line()) + "]")

    print(vuln.printVulnerabilities())

    return vulnerabilities


def main():
    check_arguments_number(sys.argv)

    get_python_as_json = parse_python(sys.argv[1])
    get_patterns = read_json_file(sys.argv[2])
    filename = extract_filename(sys.argv[1])

    patterns_list = []

    for pattern in get_patterns:
        new_pattern = Pattern(pattern["vulnerability"],pattern["sources"]
        , pattern["sanitizers"], pattern["sinks"], pattern["implicit"])
        if DEBUG : print(new_pattern.print_pattern())
        patterns_list.append(new_pattern)

    tool_policy = Policy(patterns_list)
    global GLOBAL_TOOL_POLICY
    GLOBAL_TOOL_POLICY= tool_policy

    #print(tool_policy.sinks_for_name("execute"))
    #print(tool_policy.sources_for_name("get"))
    #print(tool_policy.sanitizers_for_name("mogrify"))

    #print(tool_policy.get_vulnerability_names())
    #print("sources for XSS: " + str(tool_policy.all_sources_for_name("XSS")))
    #print("sanitizers for XSS: " + str(tool_policy.all_sanitizers_for_name("XSS")))
    #print("sinks for XSS: " + str(tool_policy.all_sinks_for_name("XSS")))
    #print("is implicit for XSS: " + str(tool_policy.is_the_name_implicit("XSS")))

    #print("ast tree in json " + str(get_python_as_json))
    #print("ast tree in dict " + str(json.dumps(get_python_as_json, indent=4)))
    #print("traverse_ast output: " + str(traverse_ast(get_python_as_json)))
    traverse_ast(get_python_as_json)
    #print("patterns: " + str(get_patterns))
    #print("Filename = " + filename)
    #policy = Policy([Pattern(p["vulnerability"], p["sources"], p["sanitizers"], p["sinks"], p["implicit"]) for p in patterns])
    #vulnerabilities = traverse_and_analyze(get_python_as_json, tool_policy)
    write_output(vuln.printVulnerabilities(), filename)
    #print(json.dumps(vulnerabilities, indent=4))
    #print(str(tool_policy.get_vulnerability_names()))
    #write_output("Ola", filename)
if __name__ == "__main__":
    main()
