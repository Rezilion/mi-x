"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from Modules import commons, constants

CVE_ID = 'CVE-2017-5754'
DESCRIPTION = f'''{CVE_ID} - Meltdown

CVSS Score: 5.6
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2017-5754

Meltdown represents critical vulnerabilities in modern processors.
Meltdown breaks the most fundamental isolation between user applications and the operating system. This attack allows a
program to access the memory, and thus also the secrets, of other programs and the operating system.
'''


def meltdown_file(debug, container_name):
    """This function checks if the meltdown file contains the 'vulnerable' string in it."""
    meltdown_path = '/sys/devices/system/cpu/vulnerabilities/meltdown'
    meltdown_content = commons.file_content(meltdown_path, debug, container_name)
    if not meltdown_content:
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format(f'Does the {meltdown_path} file contain the "vulnerable" string?'))
    if 'vulnerable' in meltdown_content:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string exists in the {meltdown_path} file'))
        return meltdown_content
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string does not exist in the {meltdown_path} '
                                                    f'file'))
    return ''


def check_vendor(debug, container_name):
    """This function checks if the vendor is affected by the meltdown vulnerabilities."""
    cpuinfo_path = '/proc/cpuinfo'
    cpuinfo_content = commons.file_content(cpuinfo_path, debug, container_name)
    if not cpuinfo_content:
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format('Does the system run with other processor than AMD?'))
    if 'AuthenticAMD' in cpuinfo_content:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('The system processor is AMD'))
        return ''
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('The system processor is not AMD'))
    return cpuinfo_content


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Meltdown."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        vendor = check_vendor(debug, container_name)
        if vendor == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif vendor:
            meltdown = meltdown_file(debug, container_name)
            if meltdown == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif meltdown:
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of Meltdown."""
    meltdown_path = '/sys/devices/system/cpu/vulnerabilities/meltdown'
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is it amd?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is it amd?', 'Not Vulnerable', label='Yes')
    vol_graph.edge('Is it amd?', f'Does {meltdown_path} file contain the "vulnerable" string?', label='No')
    vol_graph.edge(f'Does {meltdown_path} file contain the "vulnerable" string?', 'Not Vulnerable', label='No')
    vol_graph.edge(f'Does {meltdown_path} file contain the "vulnerable" string?', 'Vulnerable', label='Yes')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
