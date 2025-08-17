# Mock Test

---
## **Question 1**

SCENARIO:
Sunway University is a technological based university located at Sunway .Subang , and is amongst Malaysia’s Premier Private Universities, offering various graduate and post graduate programmes in different disciplines. The senior management of SU has directed the ICT department to address security concerns that are popping up in recent years by evaluating Information and Network security threats. Also, the senior management would like to deploy additional access and security controls to its staffs, students, administrators and faculty to prevent unauthorized activity from occurring in the campus network. So, you (Head, ICT) start to think of the expert way in addressing the security concerns raised by the senior management and finding ways to deploy additional access and security controls as directed by the senior management with proper research and findings. Before you successfully address the concerns raised by senior management, the following questions are to be answered and are as follows.

* SU is planning to implement firewall in their network. After long discussion, IT Infrastructure Manager decided to implement ZPF as an option. Discuss how Zone Based Policy Firewall works, benefits and basic configuration to implement this firewall. (10 marks)
* Discuss the fundamental principles of encryption and cryptography in the context of cybersecurity. Explain the difference between symmetric and asymmetric encryption methods, detailing how each type works and their respective strengths and weaknesses. Furthermore, explore the importance of encryption in securing data transmission and storage, providing real-world examples of encryption technologies used to protect sensitive information. (15 marks)

## **Answer:**

### **Part A: Zone-Based Policy Firewall (ZPF)**

A Zone-Based Policy Firewall (ZPF) is a modern approach to firewall configuration on Cisco routers. Instead of applying complex Access Control Lists (ACLs) to individual interfaces, a ZPF uses a more logical and scalable method based on "zones."

**How It Works:**

The core idea of a ZPF is to group interfaces with similar functions or trust levels into security zones. A security policy is then applied to control traffic that moves *between* these zones.

1.  **Create Zones:** First, you define logical zones for the network. For Sunway University, you might create zones like:
    * `SU-INTERNAL` (for the trusted staff and student LAN)
    * `INTERNET` (for the untrusted public network)
    * `DMZ-SERVERS` (for public-facing servers like the student portal or university website)

2.  **Assign Interfaces to Zones:** Each physical or virtual interface on the firewall is assigned to one of the zones. An interface can only be a member of one zone.

3.  **Define Zone-Pairs and Policies:** The real power comes from creating "zone-pairs," which define a source zone and a destination zone. You then create a policy that specifies what to do with traffic traveling between that pair. The policy inspects, passes, or drops traffic based on the rules you define.

4.  **Default Rules:**
    * Traffic moving **between two different zones** is **denied by default**. You must explicitly create a policy to permit it.
    * Traffic moving **between interfaces in the same zone** is **permitted by default**.

**Benefits:**
* **Increased Flexibility and Scalability:** It is very easy to add a new network segment. You just add a new interface and assign it to an existing zone, and it automatically inherits the zone's security policies without needing to rewrite complex ACLs.
* **Clear and Intuitive Policy:** The policy is independent of the physical interfaces. You create rules based on logical areas (like `INTERNAL` to `INTERNET`), which makes the security policy much easier to read, understand, and troubleshoot.
* **Granular Control:** ZPFs allow for stateful inspection and application-layer awareness, providing much more granular control over traffic than traditional ACLs.

**Basic Configuration Steps:**
Configuring a ZPF involves these main steps using the Modular Policy Framework (MPF):
1.  **Create a Class-Map:** To identify the specific traffic you want to control (e.g., HTTP traffic).
2.  **Create a Policy-Map:** To define the action to take on that traffic (e.g., `inspect`, `pass`, or `drop`).
3.  **Create Security Zones:** Define your logical zones.
4.  **Create a Zone-Pair:** Define the source and destination zones for the policy.
5.  **Apply the Policy-Map to the Zone-Pair:** Activate the policy.
6.  **Assign Interfaces to the Zones:** Place the physical interfaces into their respective zones.

### **Part B: Encryption and Cryptography**

**Fundamental Principles of Cryptography:**
Cryptography is the science of securing communication from adversaries. Its primary goal is to ensure the **Confidentiality, Integrity, Authentication, and Non-Repudiation** of data. Encryption is the core process within cryptography where readable data (plaintext) is converted into an unreadable format (ciphertext) using an algorithm and a secret "key." Only someone with the correct key can convert the ciphertext back into plaintext (decryption).

**Difference Between Symmetric and Asymmetric Encryption:**

The main difference lies in how they use keys.

| Feature | Symmetric Encryption | Asymmetric Encryption |
| :--- | :--- | :--- |
| **How it Works** | Uses a **single, shared secret key** for both encryption and decryption. Both the sender and receiver must have the same key. | Uses a **key pair**: a **public key** (shared with everyone) to encrypt data, and a mathematically related **private key** (kept secret) to decrypt it. |
| **Analogy** | A physical key for a lockbox. The same key locks and unlocks it. | A public mailbox with a slot (the public key) for anyone to drop letters in, but only the owner has the unique key (the private key) to open it. |
| **Strengths** | **Very fast and efficient.** It's ideal for encrypting large amounts of data. | **Solves the key distribution problem.** You can safely share your public key without compromising security. It's excellent for authentication and securely exchanging keys. |
| **Weaknesses** | **Key distribution is a major challenge.** How do you securely share the secret key with the recipient in the first place? It's not scalable for large numbers of users. | **Much slower** and more computationally intensive than symmetric encryption. Not suitable for encrypting large data streams. |
| **Examples** | AES (Advanced Encryption Standard), DES, 3DES | RSA, ECC (Elliptic Curve Cryptography) |

**Importance of Encryption in Securing Data:**

Encryption is fundamental to modern cybersecurity because it provides the primary defense for data, both when it's moving across a network and when it's stored on a device.

* **Securing Data Transmission (Data in Transit):** When you send data over an insecure network like the internet, anyone can potentially intercept it. Encryption makes this intercepted data unreadable.
    * **Real-World Example (HTTPS):** When you browse a website using HTTPS (like your online bank), your browser and the server use a hybrid approach. They first use **asymmetric** encryption (RSA) to securely exchange a temporary, shared key. Then, they use that key with a fast **symmetric** algorithm (AES) to encrypt all the data for the rest of your session. This gives you the best of both worlds: secure key exchange and high-speed data protection.
    * **Real-World Example (VPNs):** A VPN uses protocols like IPsec to create an encrypted "tunnel" over the internet, protecting all of Sunway University's remote traffic.

* **Securing Data Storage (Data at Rest):** If a laptop or server is stolen, the data on its hard drive is vulnerable. Encryption protects this stored data.
    * **Real-World Example (Full-Disk Encryption):** Technologies like BitLocker (Windows) and FileVault (macOS) use symmetric encryption (AES) to encrypt the entire hard drive. Without the password or recovery key, the data is just a meaningless jumble of bits, protecting the sensitive university research or student records on it.

---
## **Question 2**

* SU has decided to block all unwanted website e.g gambling, adult, and hacking. To begin with, access control lists (ACL) are used to prevent user from SU user to access. Describe TEN (10) good practices of ACL. (10 marks)
* Lecturer and students are increasingly connecting to SU networks remotely via mobile devices such as laptops, tablets and smartphones. Remote access needs to satisfy five essential requirements to be efficient and secure. Identify and briefly explain each of these FIVE (5) requirements. (15 marks)

## **Answer:**

### **Part A: Ten Good Practices of ACLs**

To effectively block unwanted websites and secure the Sunway University network, the following ten best practices should be followed when implementing Access Control Lists (ACLs):

1.  **Place Extended ACLs Close to the Source:** To block outbound traffic to gambling sites, an extended ACL should be placed on the LAN-facing interface of the router closest to the students. This stops unwanted traffic from crossing the campus network and consuming bandwidth.
2.  **Place Standard ACLs Close to the Destination:** Because standard ACLs only filter by source address, placing them near the source can unintentionally block legitimate traffic. They should always be placed as close to the destination device or network as possible.
3.  **Use Named ACLs:** Instead of using numbers (e.g., `access-list 101`), use descriptive names (e.g., `ip access-list extended BLOCK-WEBSITES`). This makes the purpose of the ACL immediately clear and easier to manage.
4.  **Structure the ACL Logically:** Place more specific rules at the top of the ACL. The router processes rules sequentially and stops at the first match, so a specific `deny` rule for a single website must come before a general `permit` rule for all web traffic.
5.  **Always Include an Explicit `permit` Rule:** Every ACL has an invisible `deny any any` at the end. If you only add `deny` statements to block websites, you will accidentally block all other traffic as well. You must have a final `permit ip any any` (or a more specific `permit`) to allow legitimate traffic.
6.  **Use Remarks for Documentation:** Use the `remark` command within the ACL to add comments explaining what each line or section is intended to do. This is crucial for future troubleshooting and for other administrators to understand the policy.
7.  **Create ACLs in a Text Editor:** For any ACL with more than a few lines, it is much safer to type it out in a text editor like Notepad first. This allows you to review it for errors before pasting the entire configuration into the router, preventing mistakes.
8.  **Use Object Groups (on Firewalls):** On devices like the Cisco ASA, group IP addresses of banned sites into a "network object group" and protocols into a "service object group." This allows you to write a single, clean ACL rule that references these groups, making the policy much simpler.
9.  **Apply ACLs to the Correct Interface and Direction:** Be very careful to apply the ACL to the correct interface (e.g., the student LAN interface) and in the correct direction (`in` or `out`). Applying an outbound filter in the wrong direction can have no effect or block the wrong traffic.
10. **Restrict Management Access (VTY Lines):** In addition to filtering user traffic, create a separate ACL to restrict administrative access (SSH/Telnet) to the network devices. This ACL should only permit access from specific IT staff workstations.

### **Part B: Five Requirements for Secure Remote Access**

For lecturers and students connecting to the Sunway University network remotely, the remote access solution must be both efficient and highly secure. This requires satisfying five essential requirements:

1.  **Strong Authentication:** This is the first step to verify the identity of the remote user. A simple username and password are no longer sufficient. The university must implement **Multi-Factor Authentication (MFA)**, which requires the user to provide something they know (a password) plus something they have (a code from a mobile app or a physical token). This ensures that a stolen password alone cannot grant an attacker access.

2.  **Confidentiality and Integrity (Secure Tunnel):** The connection itself, which travels over the public internet, must be protected from eavesdropping and tampering. This is achieved by using a **Virtual Private Network (VPN)**. The VPN creates an encrypted tunnel between the remote user's device and the university's network, ensuring all data transmitted is kept private (confidentiality) and cannot be altered in transit (integrity).

3.  **Authorization (Access Control):** Once a user is authenticated, the system must control what they are allowed to do. This is the principle of **least privilege**. A student, for example, should be authorized to access the library database and student portal, but should be denied access to the faculty's grading system or the university's financial servers. Authorization policies ensure users only have access to the resources they absolutely need.

4.  **Endpoint Security and Compliance:** The university cannot trust the device connecting to its network. A student's laptop could be infected with malware. A secure remote access solution must perform a **posture assessment** on the connecting device before granting access. This involves using a Network Access Control (NAC) system to check if the device has an up-to-date operating system, active antivirus software, and an enabled firewall. If the device is non-compliant, it can be denied access or placed in a restricted quarantine network.

5.  **Availability and Performance:** The remote access solution must be reliable and performant enough to be useful. If the VPN is constantly down or extremely slow, it will hinder learning and teaching. This requires having a scalable VPN gateway at the university that can handle many simultaneous connections, along with sufficient internet bandwidth to support the traffic from all remote users.

---
## **Question 3**

* Explain the concept of network security tunneling in detail. Discuss how tunneling protocols work to create secure communication channels over insecure networks. Provide examples of commonly used tunneling protocols and describe their specific use cases in enhancing network security. (10 marks)
* Confidentiality, Integrity and Availability (CIA) are the main attributes in security. Identify THREE (3) threats to a wireless network that could compromise security in SU. You should state the security attribute that is compromised by each threat. (15 marks)

## **Answer:**

### **Part A: Network Security Tunneling**

**Concept of Network Security Tunneling:**
Network security tunneling is a technique used to create a secure, private communication channel between two endpoints across an insecure, public network like the internet. The fundamental concept is **encapsulation**: the process of wrapping an entire data packet inside another packet.

This creates a "tunnel" where the original packet (the payload) is hidden and protected by the outer packet (the carrier). The routers and systems on the public network only see the outer packet's header and route it accordingly, completely unaware of the private data and original IP addresses contained within.

**How Tunneling Protocols Work:**
1.  **Encapsulation:** The sending gateway (e.g., a VPN router) takes the original IP packet from an internal user.
2.  **Encryption:** It then encrypts the *entire* original packet to ensure confidentiality.
3.  **New Header:** A new, public IP header is added to the encrypted packet. This new header contains the public IP address of the sending gateway as the source and the public IP address of the receiving gateway as the destination.
4.  **Transmission:** The newly formed packet is sent across the public internet.
5.  **Decapsulation:** The receiving gateway receives the packet, strips off the outer header, decrypts the contents, and forwards the original, now-unencrypted packet to the final destination on its private network.

**Examples of Tunneling Protocols:**

* **IPsec (Internet Protocol Security):** This is the industry standard for building secure VPNs.
    * **Use Case:** It is commonly used in **Tunnel Mode** to create secure **Site-to-Site VPNs** between a company's branch offices and its headquarters, or to provide highly secure **Remote-Access VPNs** for employees. It provides strong encryption, authentication, and integrity for all IP traffic.

* **SSL/TLS (Secure Sockets Layer/Transport Layer Security):** While it operates at a higher layer, it effectively creates a secure tunnel for application data.
    * **Use Case:** Its most common use is securing web traffic in the form of **HTTPS**. It is also the basis for **SSL VPNs**, which allow users to securely access corporate web applications and resources through a standard web browser without needing pre-installed VPN client software.

* **GRE (Generic Routing Encapsulation):** GRE is a simple tunneling protocol that can encapsulate a wide variety of network layer protocols. By itself, GRE does not provide any encryption.
    * **Use Case:** Its power comes from its flexibility. A common use case is to create a GRE tunnel to carry routing protocol updates or non-IP traffic between two sites, and then use **IPsec to encrypt the GRE tunnel itself**. This provides a secure and versatile solution.

### **Part B: Three Threats to a Wireless Network (CIA Triad)**

Here are three threats to the Sunway University wireless network, with the specific security attribute from the CIA (Confidentiality, Integrity, Availability) triad that is compromised by each.

1.  **Threat: Rogue Access Point**
    * **Description:** An attacker (or an unknowing staff member) plugs an unauthorized wireless access point (AP) into a live network jack in a classroom or office. This AP creates a new, unsecured wireless network that bypasses the university's main firewall and security controls. Users who connect to this rogue AP are vulnerable.
    * **Compromised Attribute: Confidentiality.** Once users are connected to the rogue AP, the attacker can easily launch a Man-in-the-Middle attack to capture and read all of their unencrypted traffic, stealing usernames, passwords, and sensitive information.

2.  **Threat: Evil Twin Attack**
    * **Description:** An attacker sets up their own malicious AP with the same SSID (Wi-Fi name) as the official university network, such as "Sunway-WiFi". They boost their signal so that nearby users' devices automatically connect to their "evil twin" instead of the legitimate AP.
    * **Compromised Attribute: Integrity.** The attacker can now intercept and modify the data being sent and received by the connected users. They could redirect a student from the legitimate student portal login page to a fake phishing page to steal their credentials, thereby compromising the integrity of the communication.

3.  **Threat: Wireless Deauthentication Flood (Denial of Service)**
    * **Description:** An attacker uses software to send a flood of spoofed "deauthentication" frames to the university's legitimate APs. These frames pretend to come from the connected users, tricking the AP into forcibly disconnecting everyone. The attacker can do this continuously, making it impossible for students and staff to maintain a stable connection.
    * **Compromised Attribute: Availability.** This attack directly targets the availability of the wireless network. Legitimate users are denied access to the network and its resources, disrupting classes, research, and all online campus activities.

---
## **Question 4**

* Your team has finally deployed the firewall with IDS (Intruder detection System) for SU and the senior management of SU appreciated your team for the successful deployment. What are the security boundary parameters you have considered for building this successful automated and procedural configuration in the firewall? Discuss in detail each of them. (10 marks)
* List and describe FIVE (5) types of security breaches that can occur at layer 2 of the OSI model. Furthermore, provide FIVE (5) recommended solutions to mitigate these vulnerabilities effectively. (15 marks)

## **Answer:**

### **Part A: Security Boundary Parameters for a Firewall**

When deploying a firewall with an Intrusion Detection System (IDS) for Sunway University, my team would have considered four key security boundary parameters. These parameters are based on the concept of security zones, where each interface on the firewall is assigned to a logical area with a specific trust level.

1.  **The Untrusted Boundary (The "Outside" Zone):** This is the parameter for the interface connected directly to the public internet. It is the most vulnerable point and is assigned the **lowest security level (e.g., 0)**. The fundamental policy here is to **deny all inbound-initiated traffic by default**. Any traffic allowed in (e.g., to a public web server) must be explicitly permitted by a specific rule. The IDS would be configured to be most aggressive in monitoring traffic coming from this zone.

2.  **The Trusted Boundary (The "Inside" Zone):** This parameter defines the interface(s) connected to the university's internal LAN, where students, faculty, and administrative staff reside. It is assigned the **highest security level (e.g., 100)**. The default policy allows traffic from this trusted zone to flow to less trusted zones (like the internet or a DMZ), but the traffic is still inspected by the firewall and IDS as it leaves.

3.  **The Demilitarized Zone (DMZ):** This is a critical boundary for any organization that hosts its own public services. It is a controlled, semi-trusted buffer network for servers that must be accessible from the internet, such as Sunway's public website, student portal, and email servers. This zone is assigned an **intermediate security level (e.g., 50)**. The policy is highly restrictive:
    * Traffic from the internet is only allowed to specific servers on specific ports (e.g., TCP ports 80/443 for web traffic).
    * Traffic from the DMZ is blocked from initiating connections to the trusted "Inside" zone to prevent a compromised web server from being used to attack the internal network.

4.  **The Policy and Inspection Framework:** This is the procedural configuration that ties the boundaries together. It consists of the **Access Control Lists (ACLs)** and **service policies** that define the rules of engagement for traffic crossing between zones. This framework specifies *which* services are allowed (e.g., HTTPS, DNS), *who* is allowed, and applies the IDS inspection rules to each flow. The core principle is **"deny by default,"** meaning no traffic is allowed unless it is explicitly permitted by a rule in this framework.

### **Part B: Five Layer 2 Security Breaches and Mitigations**

Layer 2 of the OSI model (the Data Link Layer) is where switches operate, and it is vulnerable to a number of attacks that occur within the local network. Here are five types of Layer 2 breaches and their recommended solutions.

1.  **Breach: MAC Address Flooding Attack**
    * **Description:** An attacker connects to a switch port and uses a tool to send thousands of Ethernet frames, each with a different fake source MAC address. This is done to overflow the switch's Content-Addressable Memory (CAM) table, which stores the mapping of MAC addresses to switch ports. When the table is full, the switch can no longer make intelligent forwarding decisions and enters a "fail-open" mode, acting like a simple hub and broadcasting all incoming frames to every port. This allows the attacker to capture traffic intended for other users.
    * **Mitigation: Port Security.** This feature is configured on a switch port to limit the number of MAC addresses that are allowed to send traffic through it. You can set a maximum number (e.g., 2) or even specify the exact MAC addresses allowed. If a violation occurs, the port can be configured to automatically shut down, preventing the attack.

2.  **Breach: DHCP Spoofing Attack**
    * **Description:** An attacker connects a rogue DHCP server to the network. This rogue server starts responding to DHCP requests from legitimate clients, handing out fake IP address information. It typically tells clients that the attacker's machine is the default gateway. As a result, all outbound traffic from the victims is sent to the attacker first, allowing for a Man-in-the-Middle attack.
    * **Mitigation: DHCP Snooping.** This security feature allows a switch to "snoop" or inspect DHCP messages. You configure switch ports as either "trusted" (where the legitimate DHCP server is connected) or "untrusted" (all other user-facing ports). The switch will then drop any DHCP server messages that come from an untrusted port, blocking the rogue server.

3.  **Breach: ARP Poisoning (ARP Spoofing)**
    * **Description:** Address Resolution Protocol (ARP) is stateless and trusts any reply it receives. An attacker can exploit this by sending unsolicited, forged ARP replies to other hosts on the LAN. For example, the attacker can tell a victim's PC that the MAC address for the default gateway is the attacker's own MAC address. The victim's PC will update its ARP cache and begin sending all its traffic to the attacker, believing it's the gateway.
    * **Mitigation: Dynamic ARP Inspection (DAI).** DAI works in conjunction with DHCP Snooping. It maintains a trusted database of IP-to-MAC address bindings learned from the DHCP server. It then inspects every ARP packet on untrusted ports and drops any that do not match a valid entry in the database, effectively preventing ARP poisoning.

4.  **Breach: VLAN Hopping Attack**
    * **Description:** This attack allows an attacker on one VLAN to gain unauthorized access to traffic on another VLAN. One common method is "switch spoofing," where an attacker's machine emulates a switch and uses the Dynamic Trunking Protocol (DTP) to negotiate a trunk link with the real switch. Once a trunk is formed, the attacker can receive traffic from all VLANs.
    * **Mitigation: Secure Trunk and Access Port Configuration.** Best practices include:
        * Explicitly configuring user-facing ports as access ports (`switchport mode access`).
        * Disabling DTP on all user-facing ports (`switchport nonegotiate`).
        * Assigning all unused ports to an unused "blackhole" VLAN and shutting them down.

5.  **Breach: Spanning Tree Protocol (STP) Manipulation**
    * **Description:** The Spanning Tree Protocol (STP) prevents loops in a switched network by electing a "root bridge." An attacker can send specially crafted STP packets (BPDUs) with a superior priority to try and become the root bridge. If successful, they can cause network traffic to be redirected through their device, allowing them to capture or manipulate it.
    * **Mitigation: BPDU Guard.** This feature should be enabled on all user-facing ports (access ports). These ports should never receive BPDUs, as they are only meant to connect end devices, not other switches. If a port with BPDU Guard enabled receives a BPDU packet, it is immediately put into an "err-disabled" state (shut down), preventing the attacker from manipulating the STP topology.
