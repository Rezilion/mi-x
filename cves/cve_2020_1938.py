"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import run_command, commons, constants

CVE_ID = 'CVE-2020-1938'
DESCRIPTION = f'''{CVE_ID} - GhostCat

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2020-1938

The vulnerability is a file read/inclusion vulnerability in the AJP connector in Apache Tomcat that was discovered on 
february 2020 by researchers at Chaitin.
The AJP protocol is enabled by default on port 8009 on the following affected Apache Tomcat versions: 
6.x.x, 7.x.x up to including 7.0.99, 8.5.x up to including 8.5.50 and 9.0.0 up to including 9.0.30.
GhostCat allows an attacker to retrieve arbitrary files from anywhere in the web application, including the `WEB-INF` 
and `META-INF` directories and any other location that can be reached via ServletContext.getResourceAsStream(). 
A remote, unauthenticated attacker could exploit this vulnerability to read web application files from a vulnerable 
server, upload files and process them in the web application as JSP which can cause Remote Code Execution (RCE) attack.

Related Links:
https://www.tenable.com/blog/cve-2020-1938-ghostcat-apache-tomcat-ajp-file-readinclusion-vulnerability-cnvd-2020-10487
https://www.trendmicro.com/en_us/research/20/c/busting-ghostcat-an-analysis-of-the-apache-tomcat-vulnerability-cve-2020-1938-and-cnvd-2020-10487.html
'''
HOST = 'host'
TOMCAT_ENVIRONMENT = 'TOMCAT_VERSION='
CATALINA_ENVIRONMENT = 'CATALINA_HOME='
PATCHED_VERSIONS = ['7.0.99', '8.5.50', '9.0.30']
AJP_DEFAULT_LINE = 'protocol="AJP'
MITIGATION = '<!--Connector port'
REQUIRED_SECRET_MITIGATION = 'requiredSecret='


def check_mitigation(printenv, debug, container_name):
    """This function checks the mitigation in the server.xml file: commenting out the line that enables AJP by default and
    has the required secret parameter set."""
    tomcat_path = ''
    for value in printenv.split('\n'):
        if value.startswith(CATALINA_ENVIRONMENT):
            tomcat_path = value.split('=')[1]
    print(constants.FULL_QUESTION_MESSAGE.format('Is CATALINA_HOME environment variable available?'))
    if not tomcat_path:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        return constants.UNSUPPORTED
    print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
    server_xml_path = f'{tomcat_path}/conf/server.xml'
    content = commons.file_content(server_xml_path, debug, container_name)
    if not content:
        return constants.UNSUPPORTED
    print(constants.FULL_QUESTION_MESSAGE.format('Is AJP enabled in the server.xml file?'))
    for line in content:
        if AJP_DEFAULT_LINE in line and MITIGATION in line:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('The default line enabling AJP in the server.xml is '
                                                            'disabled'))
            return True
        elif AJP_DEFAULT_LINE in line and MITIGATION not in line and REQUIRED_SECRET_MITIGATION in line:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('The default line enabling AJP in the server.xml set the '
                                                            'required secret parameter enabled\nWe can not determine '
                                                            'exploitability in this situations, however it is a '
                                                            'mitigation that hardens the attack'))
            return constants.UNSUPPORTED
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('The default line enabling AJP in the server.xml is enabled'))
    return False


def tomcat_version(printenv):
    """This function checks if the tomcat version is affected."""
    version = ''
    for value in printenv.split('\n'):
        if value.startswith(TOMCAT_ENVIRONMENT):
            version = value.split('=')[1]
    print(constants.FULL_QUESTION_MESSAGE.format('Is it Apache Tomcat?'))
    if not version:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('This is not an Apache Tomcat'))
        return version
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('This is an Apache Tomcat'))
    return commons.check_patched_version('Apache Tomcat', version, PATCHED_VERSIONS)


def printenv_content(debug, container_name):
    """This function get the printenv content."""
    printenv_command = 'printenv'
    pipe_printenv = run_command.command_output(printenv_command, debug, container_name)
    printenv_output = pipe_printenv.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('There are existing environment variables?'))
    if not printenv_output:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported printenv value'))
        return constants.UNSUPPORTED
    print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
    return printenv_output


def validate(debug, container_name):
    """This function validates if the host is vulnerable to GhostCat vulnerabilities."""
    if container_name:
        if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
            printenv = printenv_content(debug, container_name)
            if printenv == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif printenv:
                if tomcat_version(printenv):
                    mitigation = check_mitigation(printenv, debug, container_name)
                    if mitigation == constants.UNSUPPORTED:
                        print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
                    elif mitigation:
                        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
                    else:
                        print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_SUPPORTED_MESSAGE.format(HOST))
        print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of GhostCat."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is it an Apache Tomcat?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is it an Apache Tomcat?', 'Is the Apache Tomcat version affected?', label='Yes')
    vol_graph.edge('Is it an Apache Tomcat?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the Apache Tomcat version affected?', 'Is AJP in the server.xml file enabled?', label='Yes')
    vol_graph.edge('Is the Apache Tomcat version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is AJP in the server.xml file enabled?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is AJP in the server.xml file enabled?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
