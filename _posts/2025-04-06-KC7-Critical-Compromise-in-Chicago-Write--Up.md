Critical Compromise in Chicago—ICS takes inspiration from a real-life cyberattack in 2015 in Ukraine. I highly recommend Andy Greenberg's book, _Sandworm_, for a gripping account of the malware used in this module. I found that this module starts easy and then ramps up the difficulty as things go along. I aim for people who play these modules to think about things more analytically than get the answer. I will leverage two fundamental frameworks cyber threat analysts use: MITRE ATT&CK and the Diamond Model.

MITRE ATT&CK is one of the most popular adversary attack frameworks by governments and organizations for TTPs. The Diamond Model is leveraged to make sense of a campaign with four pillars: Adversary, Capabilities, Victim, and Infrastructure. We will use the Diamond Model to recap discoveries about our adversary.

![](https://miro.medium.com/v2/resize:fit:700/1*X_e5qK45x4D_yYm3iqTZ9Q.png)

Don’t worry; this will all make sense in a bit.

For the first question in the module, we were asked to query SCADA activity.

What the heck is SCADA? SCADA (Supervisory Control and Data Acquisition) refers to systems monitoring, controlling, and managing industrial processes remotely. OK, but what does that mean?

![](https://miro.medium.com/v2/resize:fit:700/1*MLiGoMnLnicnhGg3HScmaw.png)

SCADA systems help manage critical infrastructure such as power grids and water distribution. If an adversary can plant malware into these systems, it will have drastic consequences. I recommend reading about NotPetya malware as it was the most destructive to critical infrastructure.

Enough with the diversions; let’s get to the analysis.

## PART I

We find five ProcessEvents related to SCADA and two parent processes that should raise suspicion.

![](https://miro.medium.com/v2/resize:fit:362/1*2P6d96L3TU4yUqJ_E-iOpw.png)

Let’s break down the commands briefly.

![](https://miro.medium.com/v2/resize:fit:700/1*Lwd-moUIc_NsdF3QPACzRg.png)

From the first log, BlackEnergy gathered reconnaissance about the network. We can see that it is outputting the scan results into a txt file on targets for lateral movement, and later, we will see that it allows persistence. We can refer to MITRE ATT&CK and see that scanning for network information is Gather Victim Network Information (T1590). The second process involved leveraging the curl command to download files from the website chicagogridupdates.com onto the victim’s computer. This would be Ingress Tool Transfer (T1105). Let’s look at the additional columns and see if anything jumps out.

Well…the hostname and username will be useful!

![](https://miro.medium.com/v2/resize:fit:602/1*DHC3jNA7kkwvzrUmvlJQfQ.png)

Let’s keep that in mind for the Diamond Model since we don’t know whether this username and hostname is a victim or an insider threat.

Three other events need our attention. So, let’s break down what is going on with the most relevant command, which wiped hard drives.

![](https://miro.medium.com/v2/resize:fit:700/1*f7vNVMGkWkIwzTikpHYMnA.png)

The command reads a list of IP addresses from the file C:\ProgramData\SCADA_IPs.txt). Then it reads a password from the file C:\ProgramData\Extracted_Password.txt. Using a For loop, from each IP address from the list, it remotely connects to that computer using the tool **psexec.exe**. Then it logs into that remote computer using the account administrator and the extracted password. Once connected, it executes a command that runs KillDisk.exe, a destructive tool that erases (wipes) the data on the target machine.

From the MITRE ATT@CK Framework, this is what has been identified from this single command:

![](https://miro.medium.com/v2/resize:fit:700/1*kBwJE7b6P6hPzgxmQjV15w.png)

![](https://miro.medium.com/v2/resize:fit:604/1*C7cWXjNW_C8zK8vRnlRPRQ.png)

There is a lot of information about the tools used by the adversary. Let’s leverage the Diamond Model to keep track of our findings. Since we are cyber threat analysts, we can name our adversaries. There are naming conventions, but they are not universal. There can be a write-up on that, but to stay focused, we will name this adversary SandyDesert.

![](https://miro.medium.com/v2/resize:fit:700/1*b5p72-VFVVvE3UxlW7gMvg.png)

Since BlackEnergy was the parent process, let’s look back in time and see when BlackEnergy made it onto the network. But how do we do that? Let’s cast a wide net. Since we have established that the ProcessEvents database keeps track of activity related to running programs, I would say that is a good place to assume. Trial and error the relevant column to query, and we get our timestamp.

Uh oh! We see some Beaconing activity! Which is a C2 tactic, which in this case is T1071 — Application Layer Protocol.

![](https://miro.medium.com/v2/resize:fit:700/1*sryfDUXHmw7kRHPUUzGGdA.png)

And if we look at who is doing it…remember that username and hostname we found earlier? The user executed the first instance of BlackEnergy using Explorer. It looks like we got it all figured out, eh? Let’s celebrate with a lovely apple juicebox.

![](https://miro.medium.com/v2/resize:fit:700/1*gbMqhrTGO6636D8pINuAhA.png)

BUT WAIT! Let’s see what else we can find before calling it a day. Understanding this user might help us discover how the malware was introduced before pointing fingers.

Our employee, Jibby Saetang, is a SCADA Operator. He is a person of interest and a pivot point. We learned from the previous commands that the target was SCADA systems. But is he a victim or an adversary?

Let’s look at his emails and see which ones jump out. Here is where documenting your findings comes in handy. What do we know about our adversary…? They used tools like KillDisk.exe and…a C2 domain (chicagogridupdates.com). When we narrow emails between that domain and the user, we see characteristics of a Spearphishing attack (T1566.001). Spearphishing attacks craft their emails to target specific individuals, while regular phishing attacks are broader in their approach. Spearphishing pressures its targets with urgency and authority to open attachments.

![](https://miro.medium.com/v2/resize:fit:700/1*uZLV9_P-vKf1BMYArLU_eQ.png)

After this discovery, we can be sure that Jibby Saetang is a victim and not an adversary. We can update our Diamond model to include Jibby’s username, email, and hostname. We can also label Urgent_Cyber_Threat_Alert.zip as malicious and part of SandyDesert’s capabilities.

![](https://miro.medium.com/v2/resize:fit:700/1*a0wQHg5gphP_VJCdTICGtg.png)

## PART II

**We are at the point in the module where I will not reveal the answers but provide breadcrumbs for success.**

The second part of this module is more challenging, and leveraging our documentation on the facts will help us through it. Chances are, Jibby was not our only target for spear phishing. But how would we broaden our search?

![](https://miro.medium.com/v2/resize:fit:642/1*n3bw2xfIYY27_uqjHVR54w.png)

Let’s pivot off that domain in the link. That should be a good pivot. Right?

![](https://miro.medium.com/v2/resize:fit:700/1*6oeBWQx4f6iUjSumsRrtKg.png)

Hmmmmm, four results. That’s not much to go off of. What else can we pivot on? How about the subject line?

![](https://miro.medium.com/v2/resize:fit:700/1*l7RRvpCTGj9rzsWNUJOUsw.png)

We can combine that and even have some email addresses to pivot off of, but they could be other adversaries unrelated to this campaign. Let’s think back to how spearphishing works: authority and urgency. That subject has both, but what if we simplify the subject and only include keywords? Do any of them jump out?

When you get the right combination of word(s), it will reveal multiple email addresses that sent out spearphishing emails, but there is one that will satisfy what the module is asking. Let’s move on to which IP the adversary used to log in the most. We know the C2 domain, but do we know what IPs it uses? Which of the database tables seems the most relevant to resolving domains? Do some trial and error. Do a take 10 query to see how the data is structured for the tables you haven’t visited yet. You will get two IP addresses when you query the right table.

Sure, you could do 50/50 on the question and get it right, but what if it wasn’t that simple? Say it was 10. Applying your findings to the initial question could save a lot of work. What do we associate logins with out of all the database tables?

The next question involves thinking like an adversary.

![](https://miro.medium.com/v2/resize:fit:700/1*WLArAvwyTyGlh60GzJAxow.png)

Open Source Intelligence (OSINT) involves leveraging online tools such as search engines to obtain information about subjects, in this case, targets. Most people will use their favorite search engine to start research on a topic. The research begins very broadly, and as the research matures, so do the searches. Pivoting becomes very specific. Out of all the tables, which one would be recording this activity?

The next question, “Which compromised employee’s account was used to send the first phishing email to the final victim?” involves breaking down the question. If you didn’t jump ahead, you have already collected enough information to answer this question. Since you have read this far, here is some free chicken. Think of the poor guy, Jibby, and how he got into this mess. (Also, input the name instead of the email address)

![](https://miro.medium.com/v2/resize:fit:666/1*S07qKbsO6O8egflBz4ajdw.png)

When you figure out the answer, the next question builds on it. “How many employees in total received phishing emails during the attack?” This involves messing with our search to ensure it is as broad as possible but not so broad that it overlaps with other campaigns. Think of the keywords of this phishing campaign. Another free piece of chicken is to look out for duplicate email addresses.

After those questions are answered, the rest revolve around miscellaneous tactics. One of them I would like to touch on is Living off the Land (LOTL). LOTL involves command line tools that are embedded into the operating system. Some examples would be ipconfig, nslookup, and netstat, to name a few. An adversary would use these commands to gather environmental information to accomplish their objectives. A quick search should reveal what command would be used. Take that command and query it in the most relevant table; you should get your answer.

You will complete the module after those final questions. Great work! Here is a bit free chicken of a non-spoiler Diamond Model.

![](https://miro.medium.com/v2/resize:fit:700/1*_W7dOdjt1SmUHPWVpv5GJg.png)

I cannot emphasize the importance of incorporating known frameworks when developing your answers. Sure, it adds time, but when your campaign becomes more complex, these frameworks will become your life and blood. I used MITRE ATT&CK for TTPs for this write-up, but incorporating the Kill Chain is also ideal for tracking an adversary. I wanted to keep this relatively short, but pending feedback, I can do a write-up incorporating the Kill Chain.