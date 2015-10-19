Identify what aspects of the work have been correctly implemented and what have
not. 
	I believe I have implemented all the basic funcitons correctly, but I am
not very sure because I was unable to confidently test my own code.

Collaborators: Aaron Bowen, Becky Cutler, Daniel Baigel, and (of course) Ming

Time spent on assignment: 10 hours.

Questions: Are the heuristics used in this assignment to determine incidents
"even that good"? 
	I would argue that, yes, this alarm does have some merit. While it clearly 
has its flaws (outlined further below), some alarm is better than no alarm, even 
though it does detect a number of false positives as well as repetative alerts 
for the same line (in the log analysis).

If you have spare time in the future, what would you add to the program or do
differently with regards to detecting incidents?      
	It would be beneficial to find a way to scan for other nmap scans, credit 
card leaks, and nikto scans without using match. Since match leaves a great deal 
of room for variation (because it matches very generally), we can assume that 
many of these alerts are actually false alarms. We also have repeat alarms, so 
for reading logs it would be better to remove a line once an alarm has been 
registered at that line. Searching for shellcode could also use improvement 
because my matching or shell code was not particularlly extensive.

