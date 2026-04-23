## Windows Persistence Methods
This guide will focus on how to examine common persistence areas for the Windows operating system. Attackers will often make system alterations in order to ensure whatever they're attempting to leave behind on the host will continue executing even after the user logs off or turns off the computer. 

&nbsp;

### Windows Run Keys
Attackers will manipulate the content of Run and RunOnce registry keys on the host in order to cause programs to start once the user logs on. Below you'll find the basic rundown on how these keys work and where they are located within the Windows registry

&nbsp;


Use `Run` or `RunOnce` registry keys to make a program run when a user logs on. The `Run` key makes the program run every time the user logs on, while the `RunOnce` key makes the program run one time, and then the key is deleted. These keys can be set for the user or the machine.

&nbsp;

The data value for a key is a command line no longer than 260 characters. Register programs to run by adding entries of the form _description_-_string_=_commandline_. You can write multiple entries under a key. If more than one program is registered under any particular key, the order in which those programs run is indeterminate.

&nbsp;

The Windows registry includes the following four `Run` and `RunOnce` keys:

- **HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run**
- **HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce**
- **HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run**
- **HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce**

&nbsp;

>Source: https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys

&nbsp;

```PowerShell
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' | Get-ItemProperty | Select-Object * -ExcludeProperty PS* | Format-List
```

&nbsp;

You may need to run this in an administrative PowerShell window, but this will tell you the content of the 4 registry Run Keys. This will help you determine, at a glance, whether or not any currently set Run keys link to suspicious paths/executables that shouldn't be there.
