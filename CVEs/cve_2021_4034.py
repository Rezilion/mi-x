import Modules.constants as constants
import Modules.receive_package as receive_package
import Modules.run_command as run_command
import Modules.os_type as os_type
import Modules.os_release as os_release
import Modules.commons as commons
import semver
import graphviz

CVE_ID = 'CVE-2021-4506'
DESCRIPTION = f'''{CVE_ID} - PwnKit 

CVSS Score: 9.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-45046
 
The vulnerability is in the pkexec file in Policykit Linux package.
PolicyKit is an application-level toolkit for defining and handling the policy that allows unprivileged processes to 
speak to privileged processes, in order to grant users the right to perform some tasks in certain situations.
The pkexec file can run another process with higher privileges, the same as sudo.
Due to a missing input check of argv and the fact that there is a Linux mechanism that allows argv to be only
NULL, an overflow can occur allowing reading and writing from unexpected memory regions.
This overflow allows exploits to modify variables so that unprivileged users gain root privileges.
'''
POLKIT_VERSION_FIELD = 'Version'
POLKIT_RELEASE_FIELD = 'Release'
POLICYKIT_INSTALLED_FIELD = 'Installed'
NONE = 'none'
FIXED_VERSION = '0.120'
ROOT_OWNER = '# owner: root'
SUID_FLAG = '# flags: s'
FIXED_APT = {'Ubuntu 21.10': '0.105-31ubuntu0.1', 'Ubuntu 20.04': '0.105-26ubuntu1.2',
             'Ubuntu 18.04': '0.105-20ubuntu0.18.04.6', 'Ubuntu 16.04': '0.105-14.1ubuntu0.5+esm1',
             'Ubuntu 14.04': '0.105-4ubuntu3.14.04.6+esm1', 'Debian 9': '0.105-18+deb9u2',
             'Debian 10': '0.105-25+deb10u1', 'Debian 11': '0.105-31+deb11u1', 'Debian 12 (unstable)': '0.105-31.1'}
FIXED_RPM = {'Fedora 34': ['0.117', '3.fc34'], 'Fedora 35': ['0.120', '1.fc35'],
             'CentOS 7': ['0.112', '26.el7'], 'CentOS 8': ['0.115', '13.el8'],
             'Red 6': ['0.96', '11.el6'], 'Red 7.3': ['0.112', '12.el7'], 'Red 7.4': ['0.112', '12.el7'],
             'Red 7.6': ['0.112', '18.el7'], 'Red 7': ['0.112', '26.el7'], 'Red 7.7': ['112', '22.el7'],
             'Red 8': ['0.115', '13.el8'], 'Red 8.1': ['0.115', '9.el8'], 'Red 8.2': ['0.115', '11.el8'],
             'Red 8.4': ['0.115', '11.el8']}
MIN_KERNEL_VERSION = '0'


# This function checks for pkexec existence, suid bit and user permissions.
def pkexec_info_check(debug, container_name):
    affected = False
    which_pkexec_command = 'which pkexec'
    pipe_which_pkexec = run_command.command_output(which_pkexec_command, debug, container_name)
    which_pkexec = pipe_which_pkexec.stdout
    if which_pkexec:
        pkexec_path = which_pkexec.split('\n')[constants.START]
        getfacl_command = f'getfacl {pkexec_path}'
        pipe_getfacl = run_command.command_output(getfacl_command, debug, container_name)
        getfacl = pipe_getfacl.stdout
        if getfacl:
            pkexec_info = getfacl.split('\n')
            root = False
            suid = False
            execute = False
            for field in pkexec_info:
                if field == ROOT_OWNER:
                    root = True
                elif field.__contains__(SUID_FLAG):
                    suid = True
                elif not field.startswith('#') and field.__contains__('::') and field.endswith('x'):
                    execute = True
                    break
            print(constants.FULL_QUESTION_MESSAGE.format('Does pkexec have execute permissions?'))
            if execute:
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file has execute permissions'))
                print(constants.FULL_QUESTION_MESSAGE.format('Does pkexec have suid bit?'))
                if suid:
                    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                    print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file has suid bit'))
                    print(constants.FULL_QUESTION_MESSAGE.format('Is the pkexec binary owner root?'))
                    if root:
                        affected = True
                        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                        print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file is running with root '
                                                                        'privileges'))
                    else:
                        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                        print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file is not running with root '
                                                                        'privileges'))
                else:
                    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                    print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file does not have suid bit'))
            else:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file does not have execute permissions'))
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format('The "getfacl" Linux command is not working for pkexec, '
                                                            'unsupported value'))
            return constants.UNSUPPORTED
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('The "which" Linux command is not working for pkexec, '
                                                        'unsupported value'))
        return constants.UNSUPPORTED
    return affected


# This function compare the host policykit version with the patched version.
def compare_version(polkit_fixed_version, polkit_version, patched_version, host_info, package_name):
    if semver.compare(polkit_fixed_version, polkit_version) == 1:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: {host_info}, is'
                                                        f'bigger than the patched version which is: '
                                                        f'{patched_version}'))
        return ''
    elif semver.compare(polkit_fixed_version, polkit_version) == 0:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your system has the {package_name} patched version which is: '
                                                        f'{patched_version}'))
        return ''
    else:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: {host_info}, is '
                                                        f'lower than the patched version which is: '
                                                        f'{patched_version}'))
        return polkit_fixed_version


# This function checks if the Policy Kit package is affected.
def policykit_affected_rpm(host_information, package_name, debug, container_name):
    print(constants.FULL_QUESTION_MESSAGE.format('Is there an affected PolicyKit package installed?'))
    polkit_info = receive_package.package(host_information.split(' ')[constants.START], package_name, debug,
                                          container_name)
    if polkit_info:
        polkit_info = polkit_info.split('\n')
        polkit_fixed_version = FIXED_RPM[host_information]
        check = False
        host_version = ''
        for field in polkit_info:
            if field.__contains__(POLKIT_VERSION_FIELD) and field.__contains__(polkit_fixed_version[constants.START]):
                check = True
                host_version = field.split(': ')[constants.FIRST]
            if check:
                if field.__contains__(POLKIT_RELEASE_FIELD):
                    host_release = field.split(': ')[constants.FIRST]
                    host_info = f'{host_version}-{host_release}'
                    patched_version = f'{polkit_fixed_version[constants.START]}-{polkit_fixed_version[constants.FIRST]}'
                    return compare_version(polkit_fixed_version[constants.FIRST], host_release, patched_version,
                                           host_info, package_name)
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Polkit is not installed on the host'))
        return ''


# This function checks if the Policy Kit package is affected.
def policykit_affected_apt(host_information, package_name, debug, container_name):
    print(constants.FULL_QUESTION_MESSAGE.format('Is there an affected Policy Kit package installed?'))
    polkit_info = receive_package.package(host_information.split(' ')[constants.START], package_name, debug,
                                          container_name)
    if polkit_info:
        polkit_info = polkit_info.split('\n')
        polkit_fixed_version = FIXED_APT[host_information]
        polkit_version = ''
        for field in polkit_info:
            if field.__contains__(POLICYKIT_INSTALLED_FIELD):
                polkit_version = field.split(': ')[constants.FIRST]
                break
        if not polkit_version or polkit_version.__contains__(NONE):
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('Policykit-1 is not installed on the host'))
            return ''
        return compare_version(polkit_fixed_version, polkit_version, polkit_fixed_version, polkit_version, package_name)
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Policykit-1 is not installed on the host'))
        return ''


# This function run policy check according to the package manager.
def check_policykit(host_information, debug, container_name):
    if host_information.split(' ')[constants.START] in constants.APT_DISTRIBUTIONS:
        package_name = 'policykit-1'
        return policykit_affected_apt(host_information, package_name, debug, container_name)
    elif host_information.split(' ')[constants.START] in constants.RPM_DISTRIBUTIONS:
        package_name = 'polkit'
        return policykit_affected_rpm(host_information, package_name, debug, container_name)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(
            f'The distribution value is not one of these distributions: {constants.RPM_DISTRIBUTIONS} or these '
            f'distributions: {constants.APT_DISTRIBUTIONS}'))
        return constants.UNSUPPORTED


# This function checks if the host distribution and version are affected.
def distribution_version_affected(debug, container_name):
    information_fields = ['Distribution', 'Version']
    host_information = os_release.get_field(information_fields, debug, container_name)
    print(host_information)
    print(constants.FULL_QUESTION_MESSAGE.format('Is os release affected?'))
    if host_information == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    elif host_information:
        if host_information == 'Debian 12':
            information_fields = ['Distribution', 'Version', 'Sid']
            host_information_debian = os_release.get_field(information_fields, debug, container_name)
            if host_information_debian.endswith('unstable'):
                host_information = host_information_debian
        if host_information in FIXED_APT.keys():
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'potentially affected'))
            print(constants.FULL_QUESTION_MESSAGE.format('Is there an affected PolicyKit package installed?'))

        elif host_information in FIXED_RPM.keys():
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'potentially affected'))
            return host_information
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'not affected'))
            return ''
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine os release, unsupported value'))
        return constants.UNSUPPORTED


# This function validates if the host is vulnerable to PwnKit.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        host_information = distribution_version_affected(debug, container_name)
        if host_information == constants.UNSUPPORTED:
            print(constants.FULL_UNSUPPORTED_MESSAGE)
        elif host_information:
            policykit_installed = check_policykit(host_information, debug, container_name)
            if policykit_installed == constants.UNSUPPORTED:
                print(constants.FULL_UNSUPPORTED_MESSAGE)
            elif policykit_installed:
                pkexec_info = pkexec_info_check(debug, container_name)
                if pkexec_info == constants.UNSUPPORTED:
                    print(constants.FULL_UNSUPPORTED_MESSAGE)
                elif pkexec_info:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates graph that shows the vulnerability validation process of PwnKit.
def validation_flow_chart():
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there an affected PolicyKit package installed?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there an affected PolicyKit package installed?', 'Does pkexec have execute permissions?',
                   label='Yes')
    vol_graph.edge('Is there an affected PolicyKit package installed?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does pkexec have execute permissions?', 'Does pkexec have suid bit?', label='Yes')
    vol_graph.edge('Does pkexec have execute permissions?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does pkexec have suid bit?', 'Is pkexec binary owner root?', label='Yes')
    vol_graph.edge('Does pkexec have suid bit?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is pkexec binary owner root?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is pkexec binary owner root?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
