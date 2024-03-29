"""
Support for subprocess, semver and other modules written to avoid repetitive code.
"""
import subprocess
from packaging import version
from modules import constants, graph_functions, status_functions, run_command

VULNERABILITY = 'Shellshock'
DESCRIPTION = f'''your system will be scanned for all ShellShock related CVEs.

{VULNERABILITY}
Six Bash vulnerabilities which allows remote attackers to execute arbitrary code via a crafted environment string were 
disclosed in September 2014. This bulletin addresses the vulnerabilities that have been referred to as “Bash Bug” or 
“Shellshock” and two memory corruption vulnerabilities.

CVE-2014-6271 

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-6271

GNU Bash could allow a remote attacker to execute arbitrary commands on the system, caused by an error when evaluating 
specially-crafted environment variables passed to it by the bash functionality. An attacker could exploit this 
vulnerability to write to files and execute arbitrary commands on the system.
The vulnerability is relevant for GNU Bash through 4.3.

CVE-2014-6277 

CVSS Score: 10.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2014-6277


GNU Bash could allow a remote attacker to execute arbitrary code on the system, caused by an incomplete fix related to 
the failure to properly parse function definitions in the values of environment variables. An attacker could exploit 
this vulnerability using attack vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid 
modules in the Apache HTTP Server to execute arbitrary code on the system or cause a denial of service.
The vulnerability is relevant for GNU Bash through 4.3 bash43-026.

CVE-2014-6278 

CVSS Score: 10.0
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-6278

GNU Bash could allow a remote attacker to execute arbitrary code on the system, caused by an incomplete fix related to 
the parsing of user scripts. An attacker could exploit this vulnerability to execute arbitrary code on the system or 
cause a denial of service.
The vulnerability is relevant for GNU Bash through 4.3 bash43-026.

CVE-2014-7169 

CVSS Score: 10.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2014-7169

GNU Bash could allow a remote attacker to execute arbitrary commands on the system, caused by an incomplete fix related 
to malformed function definitions in the values of environment variables. An attacker could exploit this vulnerability 
using attack vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache 
HTTP Server to write to files and execute arbitrary commands on the system.
The vulnerability is relevant for GNU Bash through 4.3 bash43-025.

CVE-2014-7186 

CVSS Score: 10.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2014-7186

GNU Bash could allow a remote attacker to execute arbitrary code on the system, caused by an out-of-bounds memory access
while handling redir_stack. An attacker could exploit this vulnerability to execute arbitrary code on the system or 
cause a denial of service.
The vulnerability is relevant for GNU Bash through 4.3 bash43-026.

Related Links:
https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf
https://unix.stackexchange.com/questions/157477/how-can-shellshock-be-exploited-over-ssh
https://www.jamieweb.net/blog/restricting-and-locking-down-ssh-users/#command
https://tidbits.com/2014/09/30/how-to-test-bash-for-shellshock-vulnerabilities/
'''
MIN_BASH_AFFECTED_VERSION = '1.0.3'
MAX_BASH_AFFECTED_VERSION = '4.3.0'
REMEDIATION = 'Upgrade bash version to 4.3.1 or higher'
MITIGATION = 'Sanitize user input and remove unneeded characters'


def cve_2014_7186(container_name):
    """This function tests if the system is vulnerable to CVE-2014-7186."""
    exploit_command = r'''bash -c "export f=1 g='() {'; f() { echo 2;}; export -f f; bash -c
                        ' echo \$f \$g; f; env | grep ^f='"'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_out = pipe_exploit_out.communicate()[0]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-7186?'))
        if 'echo' in exploit_out:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            state = status_functions.vulnerable('CVE-2014-7186')
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            state = status_functions.not_vulnerable('CVE-2014-7186')
    return state


def cve_2014_7169(container_name):
    """This function tests if the system is vulnerable to CVE-2014-7169."""
    exploit_command = '''env X='() { (a)=>\' sh -c "echo date"; cat echo; rm ./echo'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_error = pipe_exploit_out.communicate()[1]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-7169?'))
        if not exploit_error or 'No such file or directory' in exploit_error:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            state = status_functions.not_vulnerable('CVE-2014-7169')
        else:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            state = status_functions.vulnerable('CVE-2014-7169')
    return state


def cve_2014_6277_and_cve_2014_6278(container_name):
    """This function tests if the system is vulnerable to CVE-2014-6277 or CVE-2014-6278."""
    exploit_command = '''foo='() { echo vulnerable; }' bash -c foo'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_out = pipe_exploit_out.communicate()[0]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-6277 or CVE-2014-6278?'))
        if 'vulnerable' in exploit_out:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            state = status_functions.vulnerable('CVE-2014-6277 or CVE-2014-6278')
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            state = status_functions.not_vulnerable('CVE-2014-6277 or CVE-2014-6278')
    return state


def cve_2014_6271(container_name):
    """This function tests if the system is vulnerable to CVE-2014-6271."""
    exploit_command = '''env x='() { :;}; echo vulnerable' bash -c "echo test"'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    pipe_exploit_out = run_command.command_output(exploit_command, debug=False, container_name=container_name)
    exploit_out = pipe_exploit_out.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-6271?'))
    if 'vulnerable' in exploit_out:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        state = status_functions.vulnerable('CVE-2014-6271')
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        state = status_functions.not_vulnerable('CVE-2014-6271')
    return state


def is_bash_affected(bash_version):
    """This function check the bash version."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is bash version affected?'))
    if version.parse(MIN_BASH_AFFECTED_VERSION) > version.parse(bash_version) > \
            version.parse(MAX_BASH_AFFECTED_VERSION):
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Bash affected versions are between: '
                                                        f'{MIN_BASH_AFFECTED_VERSION} to {MAX_BASH_AFFECTED_VERSION}\n'
                                                        f'Your bash version which is: {bash_version}, is affected'))
        return True
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Bash affected versions are between: '
                                                        f'{MIN_BASH_AFFECTED_VERSION} to {MAX_BASH_AFFECTED_VERSION}\n'
                                                        f'Your bash version which is: {bash_version}, is not affected'))
        return False


def bash_installed(debug, container_name):
    """This functions checks if there is bash installed of the host."""
    bash_version_command = 'bash --version'
    pipe_bash_version = run_command.command_output(bash_version_command, debug, container_name)
    bash_version_information = pipe_bash_version.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('Is there bash installed?'))
    if bash_version_information and not 'failed' in bash_version_information:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Bash is installed on the system'))
        bash_version_information = bash_version_information.split('(')[0]
        bash_version = bash_version_information.split(' ')[3]
        return bash_version
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('There is no bash installed on the system'))
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to shellshock vulnerabilities."""
    state = {}
    bash_version = bash_installed(debug, container_name)
    if bash_version:
        if is_bash_affected(bash_version):
            if bash_version:
                state['CVE-2014-6271'] = cve_2014_6271(container_name)
                state['CVE-2014-6277 or CVE-2014-6278'] = cve_2014_6277_and_cve_2014_6278(container_name)
                state['CVE-2014-7169'] = cve_2014_7169(container_name)
                state['CVE-2014-7186'] = cve_2014_7186(container_name)
                for value in state:
                    if state[value] == 'vulnerable':
                        status_functions.remediation_mitigation(REMEDIATION, MITIGATION)
            else:
                state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
        else:
            state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    else:
        state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of shellshock."""
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Is bash affected by one of the CVEs?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is bash affected by one of the CVEs?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is bash affected by one of the CVEs?', 'Not Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
