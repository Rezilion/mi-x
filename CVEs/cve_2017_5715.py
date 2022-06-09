from Modules import os_type, commons, constants, os_release
import graphviz

CVE_ID = 'CVE-2017-5715'
DESCRIPTION = f'''{CVE_ID} - Spectre Variant 2

CVSS Score: 5.6
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2017-5715

Spectre represents critical vulnerabilities in modern processors.
Spectre breaks the isolation between different applications. It allows an attacker to trick error-free programs, which 
follow best practices, into leaking their secrets. In fact, the safety checks of said best practices actually increase 
the attack surface and may make applications more susceptible to Spectre
'''


# This function checks if the spectre_v2 mitigations were not disabled by the cmdline.
def check_cmdline_disabled(debug, container_name, mitigation):
    cmdline_path = '/proc/cmdline'
    cmdline_content = commons.file_content(cmdline_path, debug, container_name)
    if cmdline_content:
        print(constants.FULL_QUESTION_MESSAGE.format(f'Does {mitigation} mitigation disabled by the cmdline?'))
        if cmdline_content.__contains__(f'no{mitigation}'):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation disabled by the cmdline'))
            return False
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation is not disabled by the '
                                                            f'cmdline'))
            return True
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {cmdline_path} file does not exist'))
        return constants.UNSUPPORTED


# This function checks if there is a mitigation exists.
def check_mitigations(debug, container_name, mitigation):
    file_name = f'{mitigation}_enabled'
    mitigation_path = f'/sys/kernel/debug/x86/{file_name}'
    mitigation_file = commons.check_file_existence(mitigation_path, debug, container_name)
    if mitigation_file:
        dmesg_path = '/var/log/dmesg'
        dmesg_content = commons.file_content(dmesg_path, debug, container_name)
        if dmesg_content:
            print(constants.FULL_QUESTION_MESSAGE.format(f'Does {mitigation} mitigation present on the system?'))
            for line in dmesg_content:
                if line.__contains__(mitigation):
                    if line.lower().__contains__('not present'):
                        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation does not present '
                                                                        f'on the system'))
                        return False
                    else:
                        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {mitigation} mitigation does present on '
                                                                        f'the system'))
                        return check_cmdline_disabled(debug, container_name, mitigation)
                else:
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {dmesg_path} file does not contain the '
                                                                    f'{mitigation} string'))
                    return False
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {dmesg_path} file does not exist'))
            return constants.UNSUPPORTED
    else:
        return False


# This function checks if the meltdown file contains the 'vulnerable' string in it.
def spectre_file(debug, container_name):
    spectre_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
    spectre_content = commons.file_content(spectre_path, debug, container_name)
    if spectre_content:
        print(constants.FULL_QUESTION_MESSAGE.format(f'Does {spectre_path} file contain the "vulnerable" string?'))
        if spectre_content.__contains__('vulnerable'):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string exists it {spectre_path} file'))
            return False
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "vulnerable" string does not exist it {spectre_path}'
                                                            f' file'))
            return True
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {spectre_path} file does not exist'))
        return constants.UNSUPPORTED


# This function checks an edge case on Red Hat 5 and 6.
def check_edge_case(debug, container_name):
    version = os_release.get_field(['Distribution', 'Version'], debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format(f'Does the system meet the conditions of the edge case?'))
    if version == 'Red 5' or version == 'Red 6':
        spectre_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
        spectre_content = commons.file_content(spectre_path, debug, container_name)
        if spectre_content:
            if spectre_content.__contains__('Full retpoline'):
                cpuinfo_path = '/proc/cpuinfo'
                cpuinfo_content = commons.file_content(cpuinfo_path, debug, container_name)
                if cpuinfo_content:
                    for line in cpuinfo_content:
                        if line.startswith('flags'):
                            if line.__contains__('ibpb') and not check_mitigations(debug, container_name, 'ibpb'):
                                print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system meets the conditions of '
                                                                                f'the edge case - the distribution and'
                                                                                f'versions are Red Hat 5 or 6, the '
                                                                                f'{spectre_path} file contains the '
                                                                                f'"retpoline" strings, and the flags '
                                                                                f'field in the {cpuinfo_path} file'
                                                                                f'contains the "ibpb string and the '
                                                                                f'ibpb mitigation is disabled'))
                                return False
                            else:
                                print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system does not meet the '
                                                                                f'conditions of the edge case - because'
                                                                                f'the flags field in the {cpuinfo_path}'
                                                                                f' file may not contain the "ibpb '
                                                                                f'string or the ibpb mitigation is '
                                                                                f'disabled'))
                                return True
                        else:
                            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported {cpuinfo_path} value'))
                            return constants.UNSUPPORTED
                else:
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {cpuinfo_path} file does not exist'))
                    return constants.UNSUPPORTED
            else:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system does not meet the conditions of the edge '
                                                                f'case - because the {spectre_path} file does not '
                                                                f'contain the "Full retpoline" string'))
                return True
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {spectre_path} file does not exist'))
            return constants.UNSUPPORTED
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The system does not meet the conditions of the edge case - '
                                                        f'because the the distribution and versions are not one of the '
                                                        f'Red Hat 5 or 6'))
        return True


# This function validates if the host is vulnerable to Spectre Variant 2.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        edge_case = check_edge_case(debug, container_name)
        if edge_case == constants.UNSUPPORTED or edge_case:
            spectre = spectre_file(debug, container_name)
            if spectre == constants.UNSUPPORTED:
                ibrs = check_mitigations(debug, container_name, 'ibrs')
                if ibrs == constants.UNSUPPORTED:
                    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
                elif ibrs:
                    ibpb = check_mitigations(debug, container_name, 'ibpb')
                    if ibpb == constants.UNSUPPORTED:
                        print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
                    elif ibpb:
                        spectre_v2_mitigation = check_cmdline_disabled(debug, container_name, 'spectre_v2')
                        if spectre_v2_mitigation == constants.UNSUPPORTED:
                            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
                        elif spectre_v2_mitigation:
                            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
                        else:
                            print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
                    else:
                        print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
                else:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            elif spectre:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates a graph that shows the vulnerability validation process of Spectre Variant 2.
def validation_flow_chart():
    spectre_v2_path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
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
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
