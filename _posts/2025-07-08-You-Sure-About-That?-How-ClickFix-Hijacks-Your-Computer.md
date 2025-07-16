_Disclaimer: This content is for educational and research purposes only. Do not visit suspected ClickFix domains without proper precautions._

ReCAPTCHA is a mechanism that web servers use to distinguish humans from bots. This prevents abuse such as Distributed Denial of Service (DDoS) and unwanted traffic. If you have been online, you have encountered these prompts.

![](https://miro.medium.com/v2/resize:fit:468/1*84NN-pRcUTk2cG3Qu9vwzQ.png)

There is a sense of trust when interacting with these prompts. However, like anything that implies trust, someone will inevitably twist it for their ulterior motives. That’s where [ClickFix](https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape) comes into the picture. ClickFix is one of the most popular social engineering tactics used by threat actors to plant Remote Access Trojans (RATs) and Infostealers. The attack is relatively simple but relies on the victim to open their Run prompt on Windows. The screen prompt comes in various forms, but universally, the threat actor wants the victim to execute a command to install malicious software.

One of the most sophisticated campaigns of ClickFix is the [ClickFake Interview](https://blog.sekoia.io/clickfake-interview-campaign-by-lazarus/). The Lazarus Group has been attributed to this campaign. The campaign targets job-seeking software developers and engineers with fake job offers from cryptocurrency platforms.

In this article, I will provide a threat hunting rule that can be used on [FOFA](https://en.fofa.info/). From there, we will take a website that matches the rule and simulate a victim’s machine through a sandbox environment. I will identify IOCs and the attack chain using MITRE ATT&CK to demonstrate what is happening on a victim’s computer.

## Discovering ClickFix Domains

The most common way to encounter a ClickFix webpage is from a phishing attempt. But as a threat hunter, I want to find it in the wild and study it to protect me and everyone I know. Fortunately, @[Securityinbits](https://x.com/Securityinbits/status/1941122355365056653) identified one way to find ClickFix in the wild. At the time of writing, there were 528 results.

![](https://miro.medium.com/v2/resize:fit:468/1*CvelqHYl3Mj3evmgh12P3Q.png)

In our case, this will be a Cloudflare flavor of ClickFix. The page will look like this:

![](https://miro.medium.com/v2/resize:fit:700/1*-LRUWV5iWW-XWppwNc7MKg.png)

However, there is a limit to the amount of traffic these domains can handle.

![](https://miro.medium.com/v2/resize:fit:700/1*KRWYjDk4F-JxlOKPGrVqUg.png)

Since our threat actor is distributing this malware on the cheap, they are likely using the free tier of the [Cloudflare Workers](https://workers.cloudflare.com/) platform. Threat actors love hiding behind legitimate platforms to throw off the scent. This campaign adds legitimacy by spoofing a Cloudflare verification page. But as we will see when we encounter the site, it is anything but legitimate. This is how our threat actor gains initial access ([TA0001](https://attack.mitre.org/tactics/TA0001/)).

![](https://miro.medium.com/v2/resize:fit:468/1*UgNlnviroJbOL5svQPo6Ww.png)

## I’m Just Doing What I’m Told

For this demonstration, we will be investigating 18track-orders[.]shop. I will be using [Any Run](https://any.run/) for the sandbox analysis. I will provide a more comprehensive overview of the malware, rather than a purely technical analysis. As mentioned earlier, ClickFix operates by instructing the victim to copy and paste a line of text deceptively into their Run prompt. At first glance, we only see “I am not a robot — reCAPTCHA Verification ID: 788500”.

![](https://miro.medium.com/v2/resize:fit:700/1*d1iwI0WJXvPqdOYCe4rgIQ.png)

However, if we take that text into the notepad, we see something amiss.

![](https://miro.medium.com/v2/resize:fit:700/1*m3nsPiaVsSq5YFSF2rh2Lw.png)

What we are seeing is the victim’s machine attempting to reach out to a foreign IP address using the command-line shell. Not only that, but this command also installs the file silently so as not to alert the victim ([T1059.003](https://attack.mitre.org/techniques/T1059/003/) and [T1204.002](https://attack.mitre.org/techniques/T1204/002/)). What happens next?

![](https://miro.medium.com/v2/resize:fit:468/1*qrRE91Pt5oH-ZC11Ax_J_g.png)

## The Drop

Here is a visual of the activity of the MSI file that was executed (in RED).

![](https://miro.medium.com/v2/resize:fit:700/1*5QfjWRc65fsC29qafrmcow.png)

After the MSI file is installed, we observe that a new process masquerades by dropping a new DLL (dbghelp.dll) ([T1036.003](https://attack.mitre.org/techniques/T1036/003/)). We find that msiexec.exe drops new files and gathers reconnaissance about the victim by querying the registry and identifying components and details about the victim’s machine ([T1036.003](https://attack.mitre.org/techniques/T1036/003/), [T1033](https://attack.mitre.org/techniques/T1033/)).

![](https://miro.medium.com/v2/resize:fit:414/1*Oap_h_pn6nF_YwBYDU_o-w.png)

After msiexe completes its task, we find a new executable called Engine-Switch.exe (PID 7528). This executable starts itself in another location (C:\ProgramData\nn_auth\Engine-Switch.exe) while moving and leveraging the DLL file from the msiexec process (C:\ProgramData\nn_auth\dbghelp.dll). We also find that the code signing certificate has expired from Mirillis Sp. z o.o. (F62821D01720EC709FABE9CAAC69ADED317EF698).

![](https://miro.medium.com/v2/resize:fit:414/1*gr-dP3QGLZzqcnGVTvMlcg.png)

After this process, we find a new executable and installation under Engine-Switch.exe (PID 7536 — a new process with the same name). This executable drops another executable called [tcpvcon.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) (C:\Users\admin\AppData\Roaming\nn_auth\). This is another example of our threat actor using legitimate tools to gain insight into our victim’s machine. This process (PID 7536) triggers a YARA rule for [HIJACKLOADER](https://www.zscaler.com/blogs/security-research/technical-analysis-hijackloader), which utilizes system calls to evade monitoring by security solutions. All of these processes are staging for the next step of our attack chain, the backdoor.

![](https://miro.medium.com/v2/resize:fit:414/1*EJjwJPyvIsrQi0s9zArYzw.png)

From here, we encounter a new executable called EtherHa.exe (PID 1740) (C:\Users\admin\AppData\Local\). This payload is distributed via our Command and Control (C2) from earlier while connecting to an unusual port (49788 and 56003) on the C2 ([T1071](https://attack.mitre.org/techniques/T1071/), [T1571](https://attack.mitre.org/techniques/T1571/)). This executable appears to be [AsyncRAT](https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=Trojan%3AMSIL%2FAsyncrat), which is a notorious RAT. Our threat actor has a backdoor into the victim’s machine. At this stage, the malware has completed its attack chain and compromised the victim’s system. The file also stages Telegram, which can be assumed to communicate with a Telegram bot with credentials of the victim’s machine ([T1552.001](https://attack.mitre.org/techniques/T1552/001/)). All while running an untrusted and expired code signing certificate from 2017 (622271AF668F99BD94AC12E5EBF86E48FD50AECB).

![](https://miro.medium.com/v2/resize:fit:414/1*E8olchdqAycZ-vZ9r0lqog.png)

# Conclusion

ClickFix follows the same procedures to socially engineer the victim to input a command to download and execute a RAT. There are different flavors of ClickFix appearing to be other services, which makes vigilance more challenging. Threat actors are leveraging Cloudflare’s Workers platform to maintain a serverless solution for distributing AsyncRAT malware. There is a hardcoded IP address (217.138.194[.]181) that performs all the work, acting as both a distribution point and a C2 server. The file s.msi creates new executables through msiexec.exe, leveraging dbghelp.dll and tcpcon.exe, and overwrites them. From there, we encounter a new executable which holds the payload of AsyncRAT (EtherHa.exe). From here, the malware installs Telegram, which we can safely assume is a communication channel for a Telegram bot. This is only one of the many flavors of ClickFix, but we find that the tactics are about the same across the board.

Bonus: The threat hunting rule from FOFA will also uncover [FileFix](https://mrd0x.com/filefix-clickfix-alternative/).

## IOCs

```
217.138.194[.]181  
18track-orders[.]shop  
  
Certificates (SHA1):  
622271AF668F99BD94AC12E5EBF86E48FD50AECB  
F62821D01720EC709FABE9CAAC69ADED317EF698  
8363887511B4835B79C383ECF06FC055B5839255  
  
Files (MD5):  
Engine-Switch.exe  
4a73bc060296fddba5e8f2e29464b40e  
  
EtherHa.exe  
050132ace215b38e8311e8f3fc11a6f2  
  
dbghelp.dll  
3924780d535da21b774cd6d4ec7e785e  
  
17fd0f.msi  
11179ffe5818e3a20238ac14d371a6b3
```
