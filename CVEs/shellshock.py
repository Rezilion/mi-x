"""
Support for subprocess, semver, graphviz and other modules which written for avoiding repetitive code.
"""
import subprocess
import semver
import graphviz
from Modules import run_command, commons, constants

CVE_ID = 'Shellshock'
DESCRIPTION = f'''your system will be scanned for all ShellShock related CVEs.

{CVE_ID}
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

CVE-2014-7187 

CVSS Score: 10.0
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-7187

Off-by-one error in the read_token_word function in `parse.y` allows remote attackers to cause a denial of service 
(out-of-bounds array access and application crash) or possibly have unspecified other impact via deeply nested for 
loops, aka the "word_lineno" issue.
The vulnerability is relevant for GNU Bash through 4.3 bash43-026.
'''
MIN_BASH_VULNERABLE_VERSION = '1.0.3'
MAX_BASH_VULNERABLE_VERSION = '4.3.0'


def cve_2014_7187(container_name):
    """This function tests if the system is vulnerable to CVE-2014-7187."""
    exploit_command = '''(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ;
                         do echo done ; done) | bash | echo "CVE-2014-7187 vulnerable, word_lineno"'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_out = pipe_exploit_out.communicate()[constants.START]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-7187?'))
        if 'CVE-2014-7187 vulnerable, word_lineno' in exploit_out:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_VULNERABLE_MESSAGE.format('CVE-2014-7187'))
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format('CVE-2014-7187'))


def cve_2014_7186(container_name):
    """This function tests if the system is vulnerable to CVE-2014-7186."""
    exploit_command = r'''bash -c "export f=1 g='() {'; f() { echo 2;}; export -f f; bash -c
                        ' echo \$f \$g; f; env | grep ^f='"'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_out = pipe_exploit_out.communicate()[constants.START]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-7186?'))
        if 'echo' in exploit_out:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_VULNERABLE_MESSAGE.format('CVE-2014-7186'))
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format('CVE-2014-7186'))


def cve_2014_7169(container_name):
    """This function tests if the system is vulnerable to CVE-2014-7169."""
    exploit_command = '''env X='() { (a)=>\' sh -c "echo date"; cat echo; rm ./echo'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_error = pipe_exploit_out.communicate()[constants.FIRST]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-7169?'))
        if not exploit_error or 'No such file or directory' in exploit_error:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format('CVE-2014-7169'))
        else:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_VULNERABLE_MESSAGE.format('CVE-2014-7169'))


def cve_2014_6277_and_cve_2014_6278(container_name):
    """This function tests if the system is vulnerable to CVE-2014-6277 or CVE-2014-6278."""
    exploit_command = '''foo='() { echo vulnerable; }' bash -c foo'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    with subprocess.Popen(exploit_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) \
            as pipe_exploit_out:
        exploit_out = pipe_exploit_out.communicate()[constants.START]
        print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-6277 or CVE-2014-6278?'))
        if 'vulnerable' in exploit_out:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_VULNERABLE_MESSAGE.format('CVE-2014-6277 or CVE-2014-6278'))
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format('CVE-2014-6277 or CVE-2014-6278'))


def cve_2014_6271(container_name):
    """This function tests if the system is vulnerable to CVE-2014-6271."""
    exploit_command = '''env x='() { :;}; echo vulnerable' bash -c "echo test"'''
    if container_name:
        exploit_command = constants.DOCKER_EXEC_COMMAND.format(container_name, 'bash', exploit_command)
    pipe_exploit_out = run_command.command_output(exploit_command, debug=False, container_name=container_name)
    exploit_out = pipe_exploit_out.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('Is vulnerable to CVE-2014-6271?'))
    if 'vulnerable' in exploit_out:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_VULNERABLE_MESSAGE.format('CVE-2014-6271'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format('CVE-2014-6271'))


def is_bash_affected(bash_version):
    """This function check the bash version."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is bash version affected?'))
    if (semver.compare(bash_version, MIN_BASH_VULNERABLE_VERSION) == -1) \
            and (semver.compare(bash_version, MAX_BASH_VULNERABLE_VERSION) == 1):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your bash version is not affected'))
    else:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your bash version is affected'))


def bash_installed(debug, container_name):
    """This functions checks if there is bash installed of the host."""
    bash_version_command = 'bash --version'
    pipe_bash_version = run_command.command_output(bash_version_command, debug, container_name)
    bash_version_information = pipe_bash_version.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('Is there bash installed?'))
    if bash_version_information and not 'failed' in bash_version_information:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Bash is installed on the system'))
        bash_version_information = bash_version_information.split('(')[constants.START]
        bash_version = bash_version_information.split(' ')[3]
        return bash_version
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('There is no bash installed on the system'))
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to shellshock vulnerabilities."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        bash_version = bash_installed(debug, container_name)
        if bash_version:
            is_bash_affected(bash_version)
            if bash_version:
                cve_2014_6271(container_name)
                cve_2014_6277_and_cve_2014_6278(container_name)
                cve_2014_7169(container_name)
                cve_2014_7186(container_name)
                cve_2014_7187(container_name)
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of shellshock."""
    vol_graph = graphviz.Digraph('G', filename={CVE_ID})
    vol_graph.attr(label=f'{CVE_ID}\n\n', labelloc='t')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node('Vulnerable to CVE-2014-6271')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node('Vulnerable to CVE-2014-6277 and CVE-2014-6278')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node('Vulnerable to CVE-2014-7169')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node('Vulnerable to CVE-2014-7186')
    vol_graph.attr('node', shape='box', style='filled', color='red')
    vol_graph.node('Vulnerable to CVE-2014-7187')
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node('Not Vulnerable to CVE-2014-6271')
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node('Not Vulnerable to CVE-2014-6277 and CVE-2014-6278')
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node('Not Vulnerable to CVE-2014-7169')
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node('Not Vulnerable to CVE-2014-7186')
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node('Not Vulnerable to CVE-2014-7187')
    vol_graph.attr('node', shape='box', style='filled', color='green')
    vol_graph.node('Not Vulnerable to shellshock vulnerabilities')
    vol_graph.attr('node', shape='box', color='lightgrey')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable to shellshock vulnerabilities', label='No')
    vol_graph.edge('Is it Linux?', 'Is bash version affected?', label='Yes')
    vol_graph.edge('Is bash version affected?', 'Not Vulnerable to shellshock vulnerabilities', label='No')
    vol_graph.edge('Is bash version affected?', 'Is vulnerable to CVE-2014-6271', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-6271', 'Vulnerable to CVE-2014-6271', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-6271', 'Not Vulnerable to CVE-2014-6271', label='No')
    vol_graph.edge('Is bash version affected?', 'Is vulnerable to CVE-2014-6277 or CVE-2014-6278', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-6277 or CVE-2014-6278', 'Vulnerable to CVE-2014-6277 and CVE-2014-6278',
                   label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-6277 or CVE-2014-6278', 'Not Vulnerable to CVE-2014-6277 and '
                                                                      'CVE-2014-6278', label='No')
    vol_graph.edge('Is bash version affected?', 'Is vulnerable to CVE-2014-7169', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-7169', 'Vulnerable to CVE-2014-7169', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-7169', 'Not Vulnerable to CVE-2014-7169', label='No')
    vol_graph.edge('Is bash version affected?', 'Is vulnerable to CVE-2014-7186', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-7186', 'Vulnerable to CVE-2014-7186', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-7186', 'Not Vulnerable to CVE-2014-7186', label='No')
    vol_graph.edge('Is bash version affected?', 'Is vulnerable to CVE-2014-7187', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-7187', 'Vulnerable to CVE-2014-7187', label='Yes')
    vol_graph.edge('Is vulnerable to CVE-2014-7187', 'Not Vulnerable to CVE-2014-7187', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
