<p align="center">
<img src="https://user-images.githubusercontent.com/15197376/178677447-74914a41-4664-47af-b156-9022f094bfbb.png#center" width="400" height="200" />
</p>

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![pylint](https://user-images.githubusercontent.com/15197376/178207178-872a404a-a3c0-4442-b0ce-94a76e38848a.svg)
<img alt="blackhat-arsenal" src="https://github.com/toolswatch/badges/blob/master/arsenal/usa/2022.svg"/>


# **Am I Exploitable?**

 Author:                   2022 - Now, Rezilion

 Description:              Vulnerabilities validation

 Development:              January 2022 - Now

 Documentation:            See website, README


# Introduction

## Description
‘Am I Exploitable?’ is a python open source project that comes to meet the need of validating if your system is exploitable to specific vulnerabilities.
The project can help you understand whether you are exploitable to a specific vulnerability and explain to you what is the vulnerable component or invulnerable component in your system.
The project can create a graph that presents the validation flow according to the vulnerability checks we perform.
MI-X supports machine readable output. The results can be exported to three different file formats: json, csv and text.
After executing the tool, you will see the validation flow - it will print out which checks were performed on the host/container and at the end it will print out remediation and mitigation recommendations.
We want to create a community of researchers and programmers that can add vulnerability checks for new vulnerabilities or critical or famous vulnerabilities. Whenever a new vulnerability comes up, we can offer this service that helps people validate if they are exploitable or not.
In addition, the vulnerabilities checks we wrote so far, can be expanded with some checks we might have missed.

## Features and usage options:
* Validate if exploitable to provided cve
* Validate if exploitable to category of cves
* Get the vulnerability description
* Validate the host containers
* Present the validation flow logic as a graph.
* Export the results to one of the three format types: json, csv, text.
* Get remediation and mitigation recommendations.

An example flow graph for CVE-2021-4034 (aka PwnKit):

<img width="879" alt="PwnKit Validation Flow Graph" src="https://user-images.githubusercontent.com/15197376/187365588-2a5e8c45-0cb0-47ac-8b8f-f357a700c425.png">


Everyone is free to use 'Am I Exploitable?' under the conditions of the AGPL-3.0 License (see [LICENSE](https://github.com/Rezilion/mi-x/blob/main/LICENSE) file).
 
## Quick facts
   - **Name**:      'Am I Exploitable?'
   - **Type**:      vulnerability validation
   - **License**:   GNU AFFERO GENERAL PUBLIC LICENSE
   - **Language**:  Python3
   - **Author**:    Rezilion
   - **Required Permissions**: root preferred, not needed (may use sudo)
   
# Files

- `am_i_exploitable.py` - The main file which handles the user input and the CVEs calls.
- `cves` - Python package that contains a python file for each currently supported vulnerability.
- `modules` - Python package that contains modules.
Modules are code implementations which are used in different CVE files.


# Support Distributions

The tool supports the following Linux distributions:

Ubuntu, Debian, Red Hat, Centos, Fedora, SUSE, SLES, Amazon

Partial support for Alpine


# Color Legend

<img width="341" alt="colors" src="https://user-images.githubusercontent.com/104366208/165800276-f31d063b-f031-4569-8f61-72832c602031.png">

# Installation Requirements

Before installing MI-X, make sure your machine has the following:
1. python version 3
2. pip3
3. graphviz (optional, needed only for the graph capabilities) 
4. xdg-utils (optional, needed only for the graph capabilities)
5. openjdk with jcmd support (needed when running in container mode and the openjdk version on the container is lower than `openjdk10`)

In order to install the requirements:
1. Check your os distribution you can use the following command:
   ```
   cat /etc/os-release
   ```
2. Understand which package manager your os distribution is using:

   apt - Ubuntu, Debian
   
   yum - Red Hat, CentOS, Fedora, SUSE, SLES, Amazon

   apk - Alpine
3. Install the relevant packages using your os distribution package manager

# Dependencies Installation Requirements
In order to execute MI-X correctly, you have to install graphviz and packaging python modules requirement using pip: 
```
pip install -r requirements.txt
```

# Install MI-X

The very latest developments can be obtained via git.

1. Clone or download the project files (no compilation nor installation is required)
   ```
   git clone https://github.com/Rezilion/mi-x.git
   ```
3. Execute MI-X menu
   ```
   cd mi-x && python3 am_i_exploitable.py
   ```
   
# Execute Scanning Template

Scanning command template
```
python3 am_i_exploitable.py -v cve_yyyy_xxxx -c True -g True -f json

```

# Execute Scanning Example
Scan the machine running containers for log4shell.
```
python3 am_i_exploitable.py -v log4shell -c True -f json

```
![Executing](https://user-images.githubusercontent.com/15197376/187567107-7cd130d8-33b7-4125-894a-e2ee3171d1c2.gif)


# Arguments

## -v --vulnerability_identifier

Specifies the vulnerability that will be checked (Not set by default). 

Syntax: 
- CVE-YEAR-ID - scans your system for specific vulnerability by the vulnerability cve id
- name - scans your system for specific vulnerability by the vulnerability name
- all - scans your system for all the vulnerabilities in the cves directory

If the argument is not set, a menu message will appear presenting the currently supported vulnerabilities.

## -c --container

Scans all running containers on the host (False by default).
- When running in containers mode, the user will need to insert the user’s password for sudo use.

## -n --container_name

Scans specific containers on the host by inserting running containers names seperated by commas only (Not set by default).
- When running in containers mode, the user will need to insert the user’s password for sudo use.

## -f --format'

Exports the results to three different format types: json, csv, text
- The user will need to specify which format type the results will be exported to.

## --description

Specifies whether to see the vulnerability description or not (True by default).

## -g --graph

Specifies whether to see the validation flowchart (False by default).

## -h --help

Help to understand how to run the code

# Supported Systems

'Am I Exploitable?' currently supports Linux.

This tool is tested or confirmed to work with Linux systems.

# Development and Bugs

Found an issue, or have a great idea? Let us know:

* GitHub - https://github.com/Rezilion/mi-x.git
* E-mail - ofrio@rezilion.com

Contributions are appreciated and can be done via GitHub. 

See CONTRIBUTING.md for more information about how to submit them.

# Support

'Am I Exploitable?' is tested on most common Linux operating systems. The documentation (README) and the debugging 
information (set the debug parameter to 'True'), should cover most questions and problems. 

Bugs can be reported via GitHub, or sending an e-mail to the email address above.

# Thanks

Thanks to the community for using and supporting open source software.

Many comments, bugs/patches and questions are the key to success and ongoing motivation in developing tools like this.
