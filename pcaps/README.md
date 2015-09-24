set1.pcap

1. How many packets are there in this set?
	861

2. What protocol was used to transfer files from PC to server?
	TCP

3. Briefly describe why the protocol used to transfer the files is insecure?


4. What is the secure alternative to the protocol used to transfer files?


5. What is the IP address of the server?
	192.168.99.130

6. What was the username and password used to access the server?
	username: defcon
	password: m1ngisablowhard

7. How many files were transferred from PC to server?
	6
	
8. What are the names of the files transferred from PC to server?
	CDkv69qUsAAq8zN.jpg
	CJoWmoOUkAAAYpx.jpg
	CKBXgmOWcAAtc4u.jpg
	CLu-mOMWoAAgjkr.jpg
	CNsAEaYUYAARuaj.jpg
	COaqQWnUBAAwX3K.jpg

9. Extract all the files that were transferred from PC to server. These files must be part of your submission!

set2.pcap

10. How many packets are there in this set?
	77982

11. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
	1

12. Briefly describe how you found the username-password pairs.
	ettercap -T -r set2.pcap | grep "PASS"

13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
	username: larry@radsot.com
	password: Zelenzmej
	identify the protocol used: IMAP
	server IP: 87.120.13.118
	domain name: radsot.com
	port number: 143

14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
	larry@radsot.com
	Zelenzmej

set3.pcap

15. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
	3

16. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
	username: seymore
	password: butts
	identify the protocol used: HTTP
	server IP: 162.222.171.208
	domain name: forum.defcon.org/login
	port number: 80

	username: jeff
	password: asdasdasd
	identify the protocol used: HTTP
	server IP: 54.191.109.23
	domain name: ec2.intelctf.com/C
	port number: 80

	username: nab01620@nifty.com
	password: Nifty->takirinl
	identify the protocol used: IMAP
	server IP: 210.131.4.155
	domain name: nifty.com
	port number: 143

17. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
	2

18. Provide a listing of all IP addresses with corresponding hosts (hostname + domain name) that are in this PCAP set. Describe your methodology.
	IP: 162.222.171.208
	Host: forum.defcon.org/login
	
	IP: 54.191.109.23
	Host: ec2.intelctf.com/C

	IP: 210.131.4.155
	Host: nifty.com

General Questions

19. How did you verify the successful username-password pairs?
	After I found the IP address of a pair, I followed the TCP stream and looked at the raw output. If it displayed things like "no access" or HTTP 403 forbidden, then I inferred that the pair was not legitimate.

20. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?
	Only put login information into secured websites, such as those that start with HTTP or HTTPS.

Submission

Push your README and extracted files from set1.pcap to the private repository that I created for you in a folder named pcaps. PLEASE DO NOT PUSH THE TWO PCAP FILES TO THE FOLDER! Say that your private repository is named comp116-mchow, make sure all the files are pushed to comp116-mchow/pcaps.

References