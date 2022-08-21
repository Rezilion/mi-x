"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from modules import run_command, get_pids, commons, constants

VULNERABILITY = 'CVE-2022-22965'
DESCRIPTION = f'''{VULNERABILITY} - Spring4Shell

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-22965
 
A zero-day Remote Code Execution (RCE) vulnerability caused by an error in the mechanism which uses 
client-provided data to update the properties of an object in the Spring MVC or Spring WebFlux application. 
The vulnerability can be exploited remotely only if a Spring application is deployed as a WAR on the Apache Tomcat 
server and run on JDK 9 and higher.

Related Links:
https://www.rezilion.com/blog/spring4shell-what-you-need-to-know/
https://securitylabs.datadoghq.com/articles/spring4shell-vulnerability-overview-and-remediation/
https://www.upguard.com/blog/what-is-spring4shell
'''
MIN_AFFECTED_JAVA_VERSION = '9'
CLASSES = {'org.springframework.web.servlet.mvc.method.annotation.ServletModelAttributeMethodProcessor': 'webmvc',
           'org.springframework.web.reactive.result.method.annotation.ModelAttributeMethodArgumentResolver': 'webflux'}
VM_VERSION = '"VM.version"'


def check_java_version(pid, jcmd_command, debug):
    """This function checks the process`s java version."""
    pipe_jcmd = run_command.command_output(jcmd_command, debug, container_name='')
    jcmd = pipe_jcmd.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is the following process: {pid} java version affected?'))
    if not jcmd:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported {VM_VERSION} value'))
        return constants.UNSUPPORTED
    java_version = jcmd.split('\n')[2].split(' ')[constants.END]
    start_of_version = str(java_version.split('.')[constants.START])
    if version.parse(start_of_version) < version.parse(MIN_AFFECTED_JAVA_VERSION):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The minimum affected java version is: '
                                                        f'{MIN_AFFECTED_JAVA_VERSION}, the process`s java version which'
                                                        f' is: {java_version}, is not affected'))
        return False
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The minimum affected java version is: {MIN_AFFECTED_JAVA_VERSION}'
                                                    f', the process`s java version which is: {version}, is affected'))
    return True


def validate_processes(pids, debug, container_name):
    """This function loops over all java processes and checks if they are vulnerable."""
    for pid in pids:
        jcmd_path = 'jcmd'
        if container_name:
            jcmd_path = commons.build_jcmd_path(pid, debug, container_name)
            if jcmd_path == constants.UNSUPPORTED:
                print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(VULNERABILITY, pid))
                break
        jcmd_command = f'sudo {jcmd_path} {pid} {VM_VERSION}'
        version_affected = check_java_version(pid, jcmd_command, debug)
        if version_affected == constants.UNSUPPORTED:
            print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(VULNERABILITY, pid))
            break
        if not version_affected:
            print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, VULNERABILITY))
            break
        jcmd_command = f'sudo {jcmd_path} {pid} '
        utility = commons.available_jcmd_utilities(jcmd_command, debug)
        if utility:
            full_jcmd_command = jcmd_command + utility
            webmvc_webflux = commons.check_loaded_classes(pid, full_jcmd_command, CLASSES, debug)
            if webmvc_webflux == constants.UNSUPPORTED:
                print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(VULNERABILITY, pid))
            elif webmvc_webflux:
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process use the {webmvc_webflux} '
                                                                f'dependency'))
                print(constants.FULL_PROCESS_VULNERABLE_MESSAGE.format(pid, VULNERABILITY))
            else:
                print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, VULNERABILITY))
        else:
            print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(VULNERABILITY, pid))


def validate(debug, container_name):
    """This function validates if an instance is vulnerable to Log4Shell."""
    if commons.check_distribution_with_alpine_support(debug, container_name):
        pids = get_pids.pids_consolidation('java', debug, container_name)
        if pids:
            validate_processes(pids, debug, container_name)
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of Spring4Shell."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are there running Java processes?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running Java processes?', 'Is java version affected?', label='Yes')
    vol_graph.edge('Are there running Java processes?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is java version affected?', 'Does the process use webmvc or webflux dependencies?', label='Yes')
    vol_graph.edge('Is java version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does the process use webmvc or webflux dependencies?', 'Vulnerable', label='Yes')
    vol_graph.edge('Does the process use webmvc or webflux dependencies?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
