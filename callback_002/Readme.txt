A simple kernel-mode driver registers a callback function to create process notifications, so this function will be called when a new process is born. Dbgprint will show you the creation processes and their parameters. Additionally, the callback function will block the "notepad" process but not "Notepad" or "nOtePad" :).
You may use the Service Controller (sc.exe) for installation, "sc create [service name] binPath= [path to your .sys file] type= kernel"

Note: you should enable dbgprint in your system to see the output.

This driver is for learning purposes without any responsibility.



