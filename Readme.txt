As IR analysts, we face growing volumes of threat data and malware samples that have to be analyzed to find the incident's root cause.
The sample can be analyzed in an automated style by using Sandbox or by the traditional way that does not require massive experience in reverse engineering. Honestly, this not an issue or something that will hinder your investigation.

Unfortunately, relying on automated analysis tools will not help you when you face Kernel-mode rootkit because it's working on a low level, and as I know no mature tools can fit in this situation.

This workshop will emphasize the importance of kernel-mode (windows internal) level, yah it's a vast topic, but we will fox in this workshop on some principles related to the two techniques that heavily used by a rootkit, Minidriver and kernel callback.

We build two drivers that simulate these techniques for learning purposes, and we will see them from two angels analyst and developer.

Minidriver
this driver will demonstrate the mini driver function or filter function and the setup that needs to be done to install it in the system. The driver will block any access to any file with the name HideMe.txt, and the file can't be observed through windows explorer or cmd.


Kernel Callback
Simply register a callback function to create process notification to monitier process creation process and go further to test the capability by block notepad process.
At the same time and from different angel we will try to catch any callback functions and see if the function form legitimate driver or not by using a https://github.com/H4Security/KernelCallbacks


I hope you find what you are looking for. These tools for learning purposes, do not try them on your production. Use them is your responsibility.
