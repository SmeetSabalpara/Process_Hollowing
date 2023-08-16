# Process_Hollowing


As the name suggests, Process Hollowing is the method by which a target process's memory is 'hollowed' out and replaced with a malicious process. It was introduced in Stuxnet malware before it became popular in the APT attacks domain.

Process Hollowing is a well known code injection technique used to create a new process in a suspended state, replace its legitimate code and data with malicious code, and then resume its execution to hide the presence of the malicious activity within a legitimate-looking process.

## How to use:

Execute the follwoing command: 

```shell
Process Hollowing.exe <path to malicious file> <path to target file>
```
