"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, graph_functions, status_functions, file_functions

VULNERABILITY = 'CVE-2017-5753'
DESCRIPTION = f'''{VULNERABILITY} - Spectre Variant 1

CVSS Score: 5.6
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2017-5753

Spectre represents critical vulnerabilities in modern processors.
Spectre breaks the isolation between different applications. It allows an attacker to trick error-free programs, which 
follow best practices, into leaking their secrets. In fact, the safety checks of said best practices actually increase 
the attack surface and may make applications more susceptible to Spectre

Related Links:
https://meltdownattack.com/
https://www.techrepublic.com/article/spectre-and-meltdown-explained-a-comprehensive-guide-for-professionals/
https://events19.linuxfoundation.org/wp-content/uploads/2017/11/Spectre-Meltdown-Linux-Greg-Kroah-Hartman-The-Linux-Foundation.pdf
https://www.kernel.org/doc/Documentation/admin-guide/hw-vuln/spectre.rst
'''
REMEDIATION = ''
MITIGATION = ''


def spectre_file(debug, container_name):
    """This function checks if the meltdown file contains the 'vulnerable' string in it."""
    spectre_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v1'
    spectre_content = file_functions.get_file_content(spectre_path, debug, container_name)
    if not spectre_content:
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format(f'Does the {spectre_path} file contain the "vulnerable" string?'))
    if 'vulnerable' in spectre_content:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string exists in the {spectre_path} file'))
        return spectre_content
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string does not exist in the {spectre_path} '
                                                    f'file'))
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Spectre Variant 1."""
    state = {}
    spectre = spectre_file(debug, container_name)
    if spectre == constants.UNSUPPORTED:
        state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
    elif spectre:
        state[VULNERABILITY] = status_functions.vulnerable(VULNERABILITY)
    else:
        state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of Spectre Variant 1."""
    spectre_v1_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v1'
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', f'Does {spectre_v1_path} file contain the "vulnerable" string?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge(f'Does {spectre_v1_path} file contain the "vulnerable" string?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge(f'Does {spectre_v1_path} file contain the "vulnerable" string?', 'Vulnerable', label='Yes')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
