from Modules import os_type, commons, constants
import graphviz

CVE_ID = 'CVE-2017-5753'
DESCRIPTION = f'''{CVE_ID} - Spectre Variant 1

CVSS Score: 5.6
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2017-5753

Spectre represents critical vulnerabilities in modern processors.
Spectre breaks the isolation between different applications. It allows an attacker to trick error-free programs, which 
follow best practices, into leaking their secrets. In fact, the safety checks of said best practices actually increase 
the attack surface and may make applications more susceptible to Spectre
'''


# This function checks if the meltdown file contains the 'vulnerable' string in it.
def spectre_file(debug, container_name):
    spectre_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v1'
    spectre_content = commons.file_content(spectre_path, debug, container_name)
    if spectre_content:
        print(constants.FULL_QUESTION_MESSAGE.format(f'Does {spectre_path} file contain the "vulnerable" string?'))
        if spectre_content.__contains__('vulnerable'):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string exists it {spectre_path} file'))
            return spectre_content
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string does not exist it {spectre_path}'
                                                            f' file'))
            return ''
    else:
        return constants.UNSUPPORTED


# This function validates if the host is vulnerable to Spectre Variant 1.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        spectre = spectre_file(debug, container_name)
        if spectre == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif spectre:
            print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates a graph that shows the vulnerability validation process of Spectre Variant 1.
def validation_flow_chart():
    spectre_v1_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v1'
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', f'Does {spectre_v1_path} file contain the "vulnerable" string?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge(f'Does {spectre_v1_path} file contain the "vulnerable" string?', 'Not Vulnerable', label='No')
    vol_graph.edge(f'Does {spectre_v1_path} file contain the "vulnerable" string?', 'Vulnerable', label='Yes')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
