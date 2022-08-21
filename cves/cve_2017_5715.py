"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import commons, constants, os_release


VULNERABILITY = 'CVE-2017-5715'
DESCRIPTION = f'''{VULNERABILITY} - Spectre Variant 2

CVSS Score: 5.6
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2017-5715

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


def check_cmdline_disabled(mitigation, debug, container_name):
    """This function checks if the spectre_v2 mitigations were not disabled by the cmdline."""
    cmdline_path = '/proc/cmdline'
    cmdline_content = commons.file_content(cmdline_path, debug, container_name)
    if not cmdline_content:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {cmdline_path} file does not exist'))
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format(f'Does {mitigation} mitigation disabled by the cmdline?'))
    if f'no{mitigation}' in cmdline_content:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation disabled by the cmdline'))
        return False
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation is not disabled by the '
                                                    f'cmdline'))
    return True


def check_mitigations_components(mitigation, debug, container_name):
    """This function checks if there is a mitigation exists."""
    file_name = f'{mitigation}_enabled'
    mitigation_path = f'/sys/kernel/debug/x86/{file_name}'
    mitigation_file = commons.check_file_existence(mitigation_path, debug, container_name)
    if not mitigation_file:
        return False
    dmesg_path = '/var/log/dmesg'
    dmesg_content = commons.file_content(dmesg_path, debug, container_name)
    if dmesg_content:
        print(constants.FULL_QUESTION_MESSAGE.format(f'Does {mitigation} mitigation present on the system?'))
        for line in dmesg_content:
            if mitigation in line:
                if 'not present' in line.lower():
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('No'))
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation does not present on '
                                                                    f'the system'))
                    return False
                print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation does present on the '
                                                                f'system'))
                return check_cmdline_disabled(mitigation, debug, container_name)
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {dmesg_path} file does not contain the {mitigation} '
                                                            f'string'))
            return False
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {dmesg_path} file does not exist'))
        return constants.UNSUPPORTED


def validate_mitigations(debug, container_name):
    """This function validates whether the mitigations enabled or not."""
    ibrs = check_mitigations_components('ibrs', debug, container_name)
    if ibrs == constants.UNSUPPORTED:
        print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
    elif ibrs:
        ibpb = check_mitigations_components('ibpb', debug, container_name)
        if ibpb == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
        elif ibpb:
            spectre_v2_mitigation = check_cmdline_disabled('spectre_v2', debug, container_name)
            if spectre_v2_mitigation == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
            elif spectre_v2_mitigation:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))
            else:
                print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))
        else:
            print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))
    else:
        print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))


def spectre_file(debug, container_name):
    """This function checks if the meltdown file contains the 'vulnerable' string in it."""
    spectre_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
    spectre_content = commons.file_content(spectre_path, debug, container_name)
    if not spectre_content:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {spectre_path} file does not exist'))
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format(f'Does the {spectre_path} file contain the "vulnerable" string?'))
    if 'vulnerable' in spectre_content:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string exists in the {spectre_path} file'))
        return False
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string does not exist in the {spectre_path} '
                                                    f'file'))
    return True


def check_cpuinfo(spectre_path, debug, container_name):
    """This function checks if the cpuinfo flags field contains the ibpb string."""
    edge_case = False
    cpuinfo_path = '/proc/cpuinfo'
    cpuinfo_content = commons.file_content(cpuinfo_path, debug, container_name)
    if not cpuinfo_content:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {cpuinfo_path} file does not exist'))
        return constants.UNSUPPORTED
    for line in cpuinfo_content:
        if line.startswith('flags'):
            if 'ibpb' in line and not check_mitigations_components('ibpb', debug, container_name):
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system meets the conditions of the edge case - '
                                                                f'the distribution and versions are Red Hat 5 or 6, the'
                                                                f' {spectre_path} file contains the "retpoline" '
                                                                f'strings, and the flags field in the {cpuinfo_path} '
                                                                f'file contains the "ibpb string and the ibpb '
                                                                f'mitigation is disabled'))
            else:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system does not meet the conditions of the edge'
                                                                f' case - because the flags field in the {cpuinfo_path}'
                                                                f' file may not contain the "ibpb string or the ibpb '
                                                                f'mitigation is disabled'))
                edge_case = True
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported {cpuinfo_path} value'))
            return constants.UNSUPPORTED
    return edge_case


def check_edge_case(debug, container_name):
    """This function checks an edge case for spectre variant 2."""
    edge_case = False
    version = os_release.get_field(['Distribution', 'Version'], debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format('Does the system meet the conditions of the edge case?'))
    if 'Red 5' in version or 'Red 6' in version:
        spectre_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
        spectre_content = commons.file_content(spectre_path, debug, container_name)
        if spectre_content:
            if 'Full retpoline' in spectre_content:
                check_cpuinfo(spectre_path, debug, container_name)
            else:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system does not meet the conditions of the edge '
                                                                f'case - because the {spectre_path} file does not '
                                                                f'contain the "Full retpoline" string'))
                edge_case = True
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {spectre_path} file does not exist'))
            return constants.UNSUPPORTED
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('The system does not meet the conditions of the edge case - '
                                                        'because the the distribution and versions are not one of the '
                                                        'Red Hat 5 or 6'))
        edge_case = True
    return edge_case


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Spectre Variant 2."""
    if commons.check_linux_and_affected_distribution(VULNERABILITY, debug, container_name):
        edge_case = check_edge_case(debug, container_name)
        if edge_case == constants.UNSUPPORTED or edge_case:
            spectre = spectre_file(debug, container_name)
            if spectre == constants.UNSUPPORTED:
                validate_mitigations(debug, container_name)
            elif spectre:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))
            else:
                print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))
        else:
            print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of Spectre Variant 2."""
    spectre_v2_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Does the system meet the edge case conditions?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does the system meet the edge case conditions?', 'Vulnerable', label='Yes')
    vol_graph.edge('Does the system meet the edge case conditions?', f'Does {spectre_v2_path} file contain the '
                                                                     f'"vulnerable" string?', label='No')
    vol_graph.edge(f'Does {spectre_v2_path} file contain the "vulnerable" string?', 'Are ibpb or ibrs mitigations '
                                                                                    'enabled?', label='No')
    vol_graph.edge(f'Does {spectre_v2_path} file contain the "vulnerable" string?', 'Vulnerable', label='Yes')
    vol_graph.edge('Are ibpb or ibrs mitigations enabled?', 'Is spectre_v2 mitigation enabled?', label='Yes')
    vol_graph.edge('Are ibpb or ibrs mitigations enabled?', 'Vulnerable', label='No')
    vol_graph.edge('Is spectre_v2 mitigation enabled?', 'Not Vulnerable', label='Yes')
    vol_graph.edge('Is spectre_v2 mitigation enabled?', 'Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
