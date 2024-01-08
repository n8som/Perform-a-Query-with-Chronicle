# Perform-a-Query-with-Chronicle

<h2>Activity Overview</h2>

In this activity, I will use Chronicle, a cloud-native tool, to investigate a security incident involving phishing.

I've learned about how SIEM tools like Chronicle provide a platform for collecting, analyzing, and reporting on data from different data sources. As a security analyst, I'll use SIEM tools to identify and respond to security incidents.

<h2>Scenario</h2>

I am a security analyst at a financial services company. I receive an alert that an employee received a phishing email in their inbox. I review the alert and identify a suspicious domain name contained in the email's body: signin.office365x24.com. I need to determine whether any other employees have received phishing emails containing this domain and whether they have visited the domain. I will use Chronicle to investigate this domain.

<h2> Task 1: Launch Chronicle</h2>

On the Chronicle home page, I’ll find the current date and time, a search bar, and details about the total number of log entries. There are already a significant number of log events ingested into the Chronicle instance.

[]

<h2>Task 2: Perform a Domain Search</h2>

To begin, complete these steps to perform a domain search for the domain contained in the phishing email. Then, search for events using information like hostnames, domains, IP addresses, URLs, email addresses, usernames, and file hashes. 

1. In the search bar, type signin.office365x24.com and click Search. Under DOMAINS, signin.office365x24.com will be listed. This tells me that the domain exists in the ingested data. 

2. Click signin.office365x24.com to complete the search.

<h2>Task 3: Evaluate the Search Results</h2>

[]

After performing a domain search, I'll be in the domain view. Evaluate the search results and observe the following:

1. VT CONTEXT: This section provides the VirusTotal information available for the domain. 

2. WHOIS: This section provides a summary of information about the domain using WHOIS, a free and publicly available directory that includes information about registered domain names, such as the name and contact information of the domain owner. In cybersecurity, this information helps assess a domain's reputation and determine the origin of malicious websites. 

3. Prevalence: This section provides a graph that outlines the historical prevalence of the domain. This can be helpful when I need to determine whether the domain has been accessed previously. Usually, less prevalent domains may indicate a greater threat. 

4. RESOLVED IPS: This insight card provides additional context about the domain, such as the IP address that maps to signin.office365x24.com, which is 40.100.174.34. Clicking on this IP will run a new search for the IP address in Chronicle. Insight cards can help expand the domain investigation and further investigate an indicator to determine whether there is a broader compromise.

5. SIBLING DOMAINS: This insight card provides additional context about the domain. Sibling domains share a common top or parent domain. For example, here the sibling domain is listed as login.office365x24.com, which shares the same top domain office365x24.com with the domain I’m investigating: signin.office365x24.com.

6. ET INTELLIGENCE REP LIST: This insight card includes additional context on the domain. It provides threat intelligence information, such as other known threats related to the domains using ProofPoint's Emerging Threats (ET) Intelligence Rep List.

7. Click TIMELINE. This tab provides information about the events and interactions made with this domain. Click EXPAND ALL to reveal the details about the HTTP requests made including GET and POST requests.  A GET request retrieves data from a server while a POST request submits data to a server.

8. Click ASSETS. This tab provides a list of the assets that have accessed the domain.

<h2>Task 4: Investigate the Threat Intelligence Data</h2>

Now that I've retrieved results for the domain name, the next step is to determine whether the domain is malicious. Chronicle provides quick access to threat intelligence data from the search results that I can use to help my investigation. Follow these steps to analyze the threat intelligence data and use my incident handler's journal to record interesting data:

1. Click on VT CONTEXT to analyze the available VirusTotal information about this domain. There is no VirusTotal information about this domain. To exit the VT CONTEXT window, click the X.

2. By Top Private Domain, click office365x24.com to access the domain view for office365x24.com. Click VT CONTEXT to assess the VirusTotal information about this domain. In the pop up, I can observe that one vendor has flagged this domain as malicious. Exit the VT CONTEXT window. Click the back button in my browser to go back to the domain view for the signin.office365x24.com search.

3. Click on the ET INTELLIGENCE REP LIST insight card to expand it, if needed. Take note of the category.

<h2>Task 5: Investigate the Affected Assets and Events</h2>

Information about the events and assets relating to the domain are separated into two tabs: TIMELINE and ASSETS. TIMELINE shows the timeline of events that includes when each asset accessed the domain. ASSETS list hostnames, IP addresses, MAC addresses, or devices that have accessed the domain.

Investigate the affected assets and events by exploring the tabs:

1. ASSETS: Several different assets have accessed the domain, along with the date and time of access. Using my incident handler's journal, record the name and number of assets that have accessed the domain. 

2. TIMELINE: Click EXPAND ALL to reveal the details about the HTTP requests made, including GET and POST requests. The POST information is especially useful because it means that data was sent to the domain. It also suggests a possible successful phish. Using my incident handler's journal, take note of the POST requests to the /login.php page. For more details about the connections, open the raw log viewer by clicking the open icon.

[]

<h2> Task 6: Investigate the Resolved IP address</h2>

So far, I have collected information about the domain's reputation using threat intelligence, and I've identified the assets and events associated with the domain. Based on this information, it's clear that this domain is suspicious and most likely malicious. But before I can confirm that it is malicious, there's one last thing to investigate.

Attackers sometimes reuse infrastructure for multiple attacks. In these cases, multiple domain names resolve to the same IP address.

Investigate the IP address found under the RESOLVED IPS insight card to identify if the signin.office365x24.com domain uses another domain. Follow these steps: 

1. Under RESOLVED IPS, click the IP address 40.100.174.34.

2. Evaluate the search results for this IP address and use my incident handler's journal to take note of the following:

  - TIMELINE: Take note of the additional POST request. A new POST suggests that an asset may have been phished.
  - ASSETS: Take note of the additional affected assets.
  - DOMAINS: Take note of the additional domains associated with this IP address.

According to the available ET Intelligence Rep List, signin.office365x24.com is categorized as []

[]

[] accessed the signin.office365x24.com domain:

[]

The IP address, [], resolves to the signin.office365x24.com domain:

[]

[] POST requests were made to the signin.office365x24.com domain:

[]

[] is the target URL of the web page that the POST requests were made to: 

[]

[] are the domains the IP address 40.100.174.34 resolves to:

[]

<h2>Conclusions</h2>

In this activity, I used Chronicle to investigate a suspicious domain used in a phishing email. Using Chronicle's domain search, I was able to:

- Access threat intelligence reports on the domain
- Identify the assets that accessed the domain
- Evaluate the HTTP events associated with the domain
- Identify which assets submitted login information to the domain
- Identify additional domains 

After investigation, I determined that the suspicious domain has been involved in phishing campaigns. I also determined that multiple assets might have been impacted by the phishing campaign as logs showed that login information was submitted to the suspicious domain via POST requests. Finally, I identified two additional domains related to the suspicious domain by examining the resolved IP address. 

