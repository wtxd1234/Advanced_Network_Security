# SEC3014 Past Semester Questions - Optimized Notes

## Question 1

### Three Types of Malicious Software (9 marks)

Malicious software (malware) can compromise computer functions by bypassing access controls, and stealing or damaging data. Here are three types:

#### 1. Ransomware
**Ransomware** is a type of malicious software that blocks access to a victim's data, typically by encrypting it, until a ransom is paid. This malware directly compromises the **availability** and **integrity** of data, rendering files or entire systems unusable.

* **How it Compromises Operations:** Once a system is infected, ransomware encrypts files on the computer and any connected network drives. The user is then shown a ransom note demanding payment (usually in cryptocurrency) for a decryption key. By making data inaccessible, it can halt all business operations. It **damages data** by making it unreadable and **bypasses access controls** by seizing control of the user's files.

#### 2. Spyware
**Spyware** is malware designed to secretly install itself on a computer to gather information about the user, their computer, and their browsing habits without consent. Its main goal is to **steal data** for malicious purposes.

* **How it Compromises Operations:** Spyware runs hidden in the background, capturing sensitive information like keystrokes (keylogging), screen captures, login credentials, and credit card numbers. This information is then sent to a remote attacker. By capturing a password, spyware effectively **bypasses access controls**. It compromises data confidentiality and can also degrade system performance by consuming resources.

#### 3. Rootkit
A **rootkit** is a clandestine type of malware designed to gain privileged ("root") access to a computer while actively hiding its presence. Rootkits are dangerous because they can conceal themselves and other malware on a system.

* **How it Compromises Operations:** A rootkit modifies the core of the operating system to hide malicious files, processes, and network connections. This allows an attacker to maintain persistent control, **bypass all access controls**, steal data, install other malware, use the computer in a botnet, or disable security functions. Rootkits are extremely difficult to detect and remove because they control the system at a fundamental level.

---

### Safeguarding Methods

Organizations should set up security systems to safeguard against threats like malware, identity theft, and unauthorized access.

#### i. Anti-virus Software (3 marks)
Anti-virus software is a foundational security tool designed to **detect, prevent, and remove malware**.
* It works by scanning files and traffic for known malware patterns (**signature-based detection**).
* Modern solutions also use **heuristic analysis** to identify suspicious characteristics of new, unknown malware.
* It quarantines or deletes threats, safeguarding against data theft and unauthorized access.

#### ii. Firewall (3 marks)
A firewall acts as a security barrier between a trusted internal network and an untrusted external network (like the internet).
* Its main function is to **monitor and filter incoming and outgoing network traffic** based on a set of security rules.
* It can block traffic from suspicious IP addresses and prevent unauthorized access attempts.
* This can also stop malware from communicating with its command-and-control servers, preventing data exfiltration.

#### iii. Virtual Private Network (VPN) (3 marks)
A VPN is used to establish a **secure and encrypted connection** over a public network.
* It creates an encrypted "tunnel" between the user's device and the VPN server, scrambling all data that passes through it.
* This is vital for protecting against identity theft and unauthorized access, especially on unsecured Wi-Fi.
* By masking the user's real IP address and encrypting traffic, a VPN ensures sensitive information remains confidential and cannot be intercepted.

---

### Analysis of Phishing Email

Nathan received a suspicious email from his university and is seeking advice.

> **Subject: Important: Your Password will expire 1 day!!!!!**
>
> **Dear Sunway Students,**
>
> This email is meant for you to inform you that your Sunway University account password will expire in 2 hours. Please follow the below and update your password.
> http://www.sunway.edu.my/email
>
> Thank you
> Regards
> Sunway Security Team

#### i. Identification of Security Threat (4 marks)
The security threat is **phishing**. Phishing is a social engineering attack where an attacker deceives a victim into revealing sensitive information by impersonating a trustworthy entity.

This email shows classic signs of phishing:
* **Creation of Urgency and Fear:** The subject line ("expire 1 day!!!!!") and the body ("expire in 2 hours") create a sense of panic to rush the user into acting without thinking.
* **Impersonal Greeting:** The generic salutation "Dear Sunway Students" is a red flag. A legitimate alert would likely address the user by their name.
* **Deceptive Link:** While the link text *looks* real, the actual hyperlink would lead to a fake website designed to steal the user's login credentials.

The goal is to steal Nathan's university credentials for unauthorized access to his personal and academic data.

#### ii. Advice for Nathan (3 marks)
The most important advice is to **never click on links in suspicious emails**.
1.  Instead, he should verify the request by navigating to the official website independently.
2.  He should open a new browser window and manually type the official address (e.g., www.sunway.edu.my).
3.  From the legitimate portal, he can log in securely to check for any official notifications and update his password if needed.

This bypasses the malicious link and prevents his credentials from being stolen.

---

## Question 2

### a) SSL Connection vs. SSL Session (10 marks)

#### SSL Session
An SSL Session is a master agreement on security parameters established between a client and a server via the SSL Handshake Protocol.
* **Establishment:** Created through a resource-intensive **full handshake** where the client and server agree on the protocol version, cipher suite, and generate a shared "master secret".
* **Components:** The session state includes a **session identifier**, the peer's certificate, the **cipher suite**, and the **master secret**.
* **Reusability:** A session is long-lasting and reusable. A client can reconnect later using the session ID to perform an **abbreviated handshake** (session resumption), which saves significant computational overhead.

#### SSL Connection
An SSL Connection is the actual, transient communication channel that operates under the security rules defined by an SSL session.
* **Establishment:** A new connection is created for exchanging data and is always associated with a session. If a session already exists, new connections can be established quickly via an abbreviated handshake.
* **Relationship to Session:** Many connections can be spawned from a single session. For example, when you load a secure webpage, the first connection establishes a session. Subsequent connections for images and scripts on that page are set up rapidly under that same session.

#### Analogy and Summary
* **Analogy:** The **SSL session** is like signing a major business contract—a one-time, intensive process to agree on all terms. The **SSL connections** are the individual transactions or phone calls made under the terms of that single contract.
* **Summary:** A session is a durable, reusable security agreement, while a connection is a temporary communication link that operates under that agreement.

---

### b) Tunneling in Computer Networking (15 marks)

Tunneling is a method for transporting data from one network across an intermediate, untrusted network by encapsulating the data packets. This creates a secure, private "tunnel" through a public network like the internet.

#### How Tunneling Secures Data
Tunneling secures data transmission primarily through **encapsulation**.
1.  **Wrapping the Packet:** The original data packet (payload) is wrapped inside another packet with a public IP address that is routable over the internet.
2.  **Encryption:** Before encapsulation, the original packet is encrypted. Even if intercepted, an attacker cannot read the original data without the decryption key.
3.  **Transmission and De-encapsulation:** The encapsulated packet is sent across the untrusted network. At the destination, the receiving device removes the outer header and decrypts the original packet.

This combination of encapsulation and encryption ensures data **confidentiality** and **integrity**.

#### Common Tunneling Protocols

##### 1. IPsec (Internet Protocol Security)
A robust protocol suite that operates at the network layer, securing all traffic between two points (e.g., a site-to-site VPN).
* **Advantages:** High security with strong encryption and authentication. Transparent to applications as it secures all IP traffic.
* **Disadvantages:** Can be complex to configure. May be blocked by firewalls or NAT devices if not set up properly.

##### 2. SSL/TLS (Secure Sockets Layer/Transport Layer Security)
Operates at the application layer, often in the form of an SSL VPN. It's the same technology used for HTTPS.
* **Advantages:** Firewall-friendly as it uses standard web port 443. Offers flexible, granular access to specific applications.
* **Disadvantages:** Secures traffic on an application-by-application basis by default. Can have slightly higher performance overhead than IPsec.

##### 3. PPTP (Point-to-Point Tunneling Protocol)
One of the oldest VPN protocols, known for speed and ease of setup.
* **Advantages:** Very fast due to low computational overhead. Widely compatible and built into most operating systems.
* **Disadvantages:** **Weak Security.** Contains well-known vulnerabilities and is **no longer considered secure** for modern use.
