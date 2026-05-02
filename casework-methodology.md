## Case Methodology
For the purpose of this guide the terms cases and alerts are to be used interchangeably. When it comes to digital forensics and incident response as a role, I find it easier to frame things using criminology terms. Cybersecurity is as complex as any other advanced field, so it helps to break things down using metaphors and other descriptive language. Our job as an Analyst means we're in the business of problem solving and question answering cybersecurity concerns.

Analysts are presented with work in one of two manners:

### Detections/Alerts

This guide is intended to be SIEM agnostic, but effectively all analysts will be given work in the form of "Our security product has detected X in this environment". These are system generated alerts that require human analyst validation. How these alerts are handled will change from one organization to another, but what they all have in common is the creation of a work object. Some call them cases, some call them alerts, but they're all the same thing. "An alert or multiple correlated alerts have occurred" and our job is to determine _why_ those alerts occurred. An example of a detection/alert would be "EDR solution has detected a component of the Mimikatz toolset on host A at 11:34 PM UTC".

### Threat Hunts

Threat hunts are human generated work requests. This mostly appears as a request from a client to answer a question or address a concern of theirs. They can also be generated/performed by internal threat hunting teams that comb through environments for anomalous activity without being requested to do so. Threat hunts come in two flavors, Leadless and Lead-Driven. Lead-Driven threat hunts have evidence or IOCs (Indicators of Compromise) that would be a starting point for an investigation. A "Lead" in investigative terminology is a piece of evidence that leads us closer to the truth or helps us progress. For example, a client could request a threat hunt for host A because a user opened a malicious email on the host. This is an example of a Lead-Driven threat hunt because we've narrowed it down to a single host and a single user and a single email that need to be investigated. We have information that allows us to proceed in a logical manner. 

Leadless threat hunts are the opposite, they lack any defining evidence that would allow for a logical investigation. Whether or not Leadless threat hunts are to be performed by your role is up to your particular organization but typically Leadless style threat hunts are performed by analysts that specifically do that work. This is because the standard methodology for a Leadless hunt involves identifying an IOC on your own based on pattern recognition/multiple other factors. Once an IOC is identified by a Leadless hunt, the search field is expanded to see if that IOC is present elsewhere. Leadless threat hunts aren't to be viewed as lesser, because they still provide valid results. If an analyst is able to identify an IOC in an environment and the search is widened to include all possible hosts, they're providing much greater coverage and security than if they were to simply remediate the one IOC they found. For example, in a Leadless threat hunt, an analyst can find a RAT (Remote Access Trojan) running on Host A in Customer A's environment. If they widen their search afterwards to include not just all hosts in Customer A's environment, but Customer B and C's environments, they might find that several other hosts are infected as well with the same thing. 


## Case/Alert Handling Procedures

There's a lot of different methodologies floating around in the cybersecurity world. I'm of the opinion that one should follow industry standard best practices but not be afraid to flex some creativity and imagination when needed. It's difficult to state with confidence whether or not one method works better than another but there's some generally agreed upon best ways to proceed. Your particular organization may have different manners of how they'd like to handle cases but this is normally in regards to meeting SLA (Service Level Agreements) times.

### Triage
Triage is the first step that analysts perform. To triage an alert/case means to examine the case details and quickly determine whether or not a case meets criteria for further escalation, investigation, or resolving. This process should take no longer than 5-10 minutes. We're aiming for a quick time on this step because it's important to be able to quickly assess a threat on first glance. Cases/Alerts are normally categorized as follows: 

#### Low/Informational: 
These alerts can range from anything to "A firewall rule was changed" to "A user logged on". These alerts are typically not worthy of investigation on their own but when correlated together can form something of a higher priority. For example, a low severity detection for a USB device being plugged in can correlate with a different detection for malware being detected on a removable drive to provide greater context for the analyst.

#### Medium:
These alerts contain the most variety and normally require human validation. Alert types range from Behavioral detections like a binary reaching out to a remote IP address to other detections that require a closer look like .DLL sideloading.  If we put this alert severity in terms of odds, we have about a 50% chance of the alert being True Positive or False Positive. 

#### High:
High severity alerts are alerts that are strong indicators of compromise. Alert types range from an M365 (Microsoft 365) session containing a known malicious user-agent header was observed to Domain Trust Enumeration events like the `nltest /domain_trusts` command. [NLTEST](https://attack.mitre.org/software/S0359/). This alert severity can be understood as having a 75% to 85% chance of being performed in a malicious context. 

#### Critical: 
Critical alerts are alerts with an almost guaranteed indicator of malicious intent. Alert types range from observing the `LSASS` process having its memory dumped for credential harvesting to the theft of the DPAPI Backup Key. This alert severity can be interpreted as having a 90% to 99% likelihood of malicious context. Critical cases often become full-blown incidents that require special handling.

When understanding case/alert severities, it's always important to remember that these alerts can generate for expected activity. Clients often have simulated threats (Penetration Tests) or similar security testing that can be indistinguishable from genuine Threat Actor activity. That's why we never have a full 100% chance of malicious context. It's also important to realize that the world is full of technology that may be old, made poorly/incorrectly, or just plain bizarre. Analysts should never assume from the triage step alone whether or not a case is a True or False positive. The triage step is purely so we can assign an estimated severity before validating ourselves. 

#### Assigning severity and determining how to proceed

When a case/alert is generated it normally has a suggested severity it places the alert at, depending on what software/platform you're using. Sometimes the severity is up to the analyst to determine during the Triage stage. During the 5-10 minutes we have to triage we just need to examine the data in the alert and make our best educated guess as to what the severity should be and how to handle it. If you're sure the case is a Low severity due to the alert being marked as benign in a prior case, then it deserves to be a Low severity case. Oftentimes platforms will allow you to duplicate an alert into another for repeated instances of an alert that have been previously investigated/otherwise determined to be benign. Making this determination can be automated but analysts should be able to make this determination as well.

Moving forward with this guide, we'll cover how to proceed in the event the case is not a duplicate of prior benign activity and is not indicative of critical response efforts being required, as we'll cover that in a later post.

### Investigation

Investigations are a series of questions and answers. Our job as analysts is to find the right questions to ask that lead us to the answers we need. In the context of cybersecurity, it is our goal to determine the Who, What, When, Where, Why, and How surrounding the alert we receive. Let's run through an example so we can get a feel for what we're supposed to be doing.

We've picked up an alert for suspicious applications being observed in M365 login attempts. The alert details are as follows:


>This alert triggers when a successful login or login failure indicates successful credentials to the Office 365 application where the application contains MicrosoftO365, python-aiohttp or .net clr 3.5.30729; tablet PC 2.0. This IOC indicates an Adversary-in-the-Middle session compromise, where the user receives an email with an attachment in the form of a QR code, which ensures the user scans the QR code on an unmanaged asset. The user's browser history should be investigated to check if the potentially compromised user downloaded or viewed an attachment with a QR Code during the time around the UserLoggedIn/UserLoginFailed operation in the M365 Unified Audit Logs.


This is a real alert from the wide variety of alerts that M365 has. The alert details will continue the answers we need. Now let's start asking some important questions. The client will have these questions as well, so it's our job to get them answered. 

#### Who is the impacted user?
This information will be in the alert.

#### What is the impacted service?
M365, this is related to a user's Microsoft account, cloud-wise.

#### When did this happen?
Timestamps are everything, make sure to list them down to the second as per the alert details.

#### Where/Why/How did this happen?
I've combined these three questions because their answers are typically the same piece of evidence. Let's note an important detail from the alert we've received: `This alert triggers when a successful login or login failure indicates successful credentials to the Office 365 application where the application contains MicrosoftO365, python-aiohttp or .net clr 3.5.30729; tablet PC 2.0.` The login failure/success indicates successful credentials were used regardless. This means the account has a strong likelihood of being compromised. User account compromises are always High severity cases. Well, how did they get compromised? The alert details this further by saying: `This IOC indicates an Adversary-in-the-Middle session compromise, where the user receives an email with an attachment in the form of a QR code, which ensures the user scans the QR code on an unmanaged asset.` They even give us advice on where to look next: `The user's browser history should be investigated to check if the potentially compromised user downloaded or viewed an attachment with a QR Code during the time around the UserLoggedIn/UserLoginFailed operation in the M365 Unified Audit Logs.` 

Understanding this makes it clear what the next step of the investigation is to be. We need to investigate the browser history of the impacted user to determine their activity for the timeframe. This should reveal what caused the alert, which is normally going to be an email they received that contained a QR code. 

### Documentation and Communication:

This guide unfortunately won't be of much help when it comes to documentation, as the formatting of your own documentation should be what best makes sense to you for future reference. However, please be aware that you _should_ be documenting everything you do. The better you are at documenting what you do, the less problems you'll have in the future should something you've investigated need to be revisited by anyone. Workplaces will differ how documentation is to be shared/formatted internally. 

Communication is something I take very seriously. Being able to effectively communicate to your coworkers and clients is just as important as having a deep technical understanding. Your documentation should reflect a desire to be understood by those you need to read it. When writing documentation made to be shared internally with other technically literate or otherwise cybersecurity focused people you can use things like code blocks, syntax highlighting, or advanced terminologies more freely than you would if the documentation was customer facing. Know who's going to be reading your work and tailor it for them. 

### Closing Remarks:

There's going to be pressure from the industry in general for you to complete these tasks as quickly as possible. This pressure is at odds with the reality that the work never ends. There's always going to be cases/alerts to deal with regardless of how fast you do them. What matters is that you do your best to be as accurate as possible. It's more important that you deliver complete and accurate results than it is for you to complete the tasks as quickly as possible. There are no shortcuts. Speed comes from practice and familiarity. Anything beyond what is required of a human analyst should be solved with automation. For example, if we know that an alert has a 99% chance of malicious context, we can set up automation to perform a response to the alert being generated that will secure the environment like isolating a host, disabling an account, closing a network, etc. This can always be undone afterwards to restore the environment to working order. What _can't_ always be undone afterwards is any damage caused by a threat actor. 

Cybersecurity is a marathon, not a sprint. I'll be doing this for the rest of my life, and I'll be damned if anyone tells me I'm not giving enough. Give a damn, and it'll reflect in your work. 

