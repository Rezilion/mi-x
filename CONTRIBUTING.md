# How to contribute to Am I Really Vulnerable?

'Am I Really Vulnerable?' is an open source project. As such, all contributions and suggestions are welcome.
You can contribute in many ways: giving ideas, answering questions, reporting bugs, proposing enhancements, 
improving the documentation, fixing bugs, etc...
Many thanks in advance for every contribution.

In order to facilitate healthy, constructive behavior in an open and inclusive community, 
we all respect and abide by our code of conduct.

## How to work on an open Issue?

The list of open issues can be found at: `https://github.com/rezilion/amireallyvulnerable/issues`

Some of them may have the label `help wanted`: that means that any contributor is welcomed!
If you would like to work on any of the open Issues:
- Make sure it is not already assigned to someone else. 
The assignee (if any) can be found on the top of the right column of the Issue page. 
- You can self-assign it by commenting on the Issue page with one of the keywords: `#take` or `#self-assign`. 
- Work on your self-assigned issue and eventually create a Pull Request.


## How to create a Pull Request?

1. Fork the repository by clicking on the `Fork` button on the repository's page. This creates a copy of the code under your GitHub user account. 
2. Clone your fork to your local disk, and add the base repository as a remote:

```
git clone git@github.com:<your GitHub handle>/amireallyvulnerable.git
cd datasets
git remote add upstream https://github.com/rezilion/amireallyvulnerable.git
```

3. Create a new branch to hold your development changes:
```
git checkout -b a-descriptive-name-for-my-changes
```
Do not work on the master branch.

Make sure the branch name references the vulnerability CVE or name.

5. Set up a development environment by running the following command in a virtual environment:
`pip install -e ".[dev]"`
(If amireallyvulnerable was already installed in the virtual environment, remove it with 
`pip uninstall amireallyvulnerable` before reinstalling it in editable mode with the -e flag.)

6. Develop the features in your branch. 
If you want to add a CVE file or module see more detailed instructions in the `How to add a CVE file or module` section.

7. Format your code. 

8. Once you're happy with your code, add your changes and make a commit to record your changes locally:
```
git add <your_file_name>
git commit
```
It is a good idea to sync your copy of the code with the original repository regularly. 
This way you can quickly account for changes:
```
git fetch upstream
git rebase upstream/master
```
Push the changes using:
```
git push -u origin a-descriptive-name-for-my-changes
```
10. Once you are satisfied, go to the webpage of your fork on GitHub,
Click on `"Pull request"` to send it to the project maintainers for review.


## How to add a CVE file or module?

1. Each CVE file should contain the following items:
- `DESCRIBE` - Constant variable which saves the description of the vulnerability.
- `validate()` - Function which performs the CVE validation.
- `validation_flow_chart()` - Function which creates the CVE validation flow graph.
- `main()` - The main function, prints the DESCRIBE, calls the functions, and calls the next CVE if necessary. 
2. Each module file should consist of functions.
3. CVE files are placed under the `CVEs` python package and modules are placed under the `Modules` python package.
4. Use `Modules` as much you can, We want to automate the project as much we can and avoid duplication of code.
5. Prints in the code will only be through the messages in the `constants` module. 
6. Constants variable should be capitalized with underscore as word separator.
7. Files, functions and variables are lower-case with underscore as word separator.
8. Make sure to add the vulnerability to the constants variable `ALL_VULNERABILITIES`
(if needed, add it to the `DUPLICATE_VULNERABILITIES_NAMES` variable as well)