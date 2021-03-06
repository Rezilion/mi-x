"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import run_command, commons, constants

CVE_ID = 'CVE-2015-0235'
DESCRIPTION = f'''Ghost

CVSS Score: 6.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2015-0235

{CVE_ID} is a Heap-based buffer overflow vulnerability in the __nss_hostname_digits_dots function .
This vulnerability allows a remote attacker that is able to make an application call to gethostbyname*() functions to
execute arbitrary code with the permissions of the user running the application.
The affected glibc versions are between 2.2 to 2.17 (the fix was introduced in version 2.18).
'''
MIN_AFFECTED_VERSION = '2.2'
MAX_AFFECTED_VERSION = '2.17'


def glibc_version(glibc_value):
    """This function checks if the GLIBC version is affected."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is GLIBC version affected?'))
    if MAX_AFFECTED_VERSION <= glibc_value <=  MAX_AFFECTED_VERSION:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected GLIBC versions are between {MIN_AFFECTED_VERSION} '
                                                        f'to {MAX_AFFECTED_VERSION}'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your GLIBC version which is: {glibc_value} is affected'))
        return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected GLIBC versions are between {MIN_AFFECTED_VERSION} '
                                                    f'to {MAX_AFFECTED_VERSION}'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your GLIBC version which is: {glibc_value} is not affected'))
    return False


def glibc_exist(debug, container_name):
    """This function checks if GLIBC exists."""
    glibc_command = 'ldd --version'
    pipe_glibc = run_command.command_output(glibc_command, debug, container_name)
    glibc_output = pipe_glibc.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('There is GLIBC?'))
    if not glibc_output:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported GLIBC value'))
        return constants.UNSUPPORTED
    if 'GLIBC' in glibc_output or 'GNU libc' in glibc_output:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('GLIBC does exist'))
        return glibc_output.split('\n')[constants.START].split(' ')[-1]
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('GLIBC does not exist'))
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Ghost vulnerabilities."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        glibc_value = glibc_exist(debug, container_name)
        if glibc_value == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif glibc_value:
            if glibc_version(glibc_value):
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Ghost."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there GLIBC?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there GLIBC?', 'Is the GLIBC version affected?', label='Yes')
    vol_graph.edge('Is there GLIBC?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the GLIBC version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the GLIBC version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
