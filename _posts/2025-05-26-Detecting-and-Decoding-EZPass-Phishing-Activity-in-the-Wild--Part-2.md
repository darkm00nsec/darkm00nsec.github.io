_Disclaimer: This article is for research and educational purposes. Do not visit phishing websites without proper precautions._

To recap the previous section, I found a pattern in how the E-ZPass sites are named and that the domains share the same HTTP Headers as the IPs that resolve them. This exposed a ton of IOCs, including IP addresses used by our threat actor. But I thought I hit a dead end. I was looking around, and I thought I ran out of pivots. The main issue was that I had yet to make a connection to a phishing site!

![](https://miro.medium.com/v2/resize:fit:490/1*TNZ4C7IJvwD4d1jcFJtHgg.png)

I didn’t understand why. My theory was that Internet Service Providers (ISPs) and platforms such as Google flagged the phishing sites to prevent people from visiting them. I had discovered a pattern, and it would make sense that the big players found it, too. Also, it doesn’t help that they change their domains and IPs frequently. I started looking around online for what I could do. The most significant help was that a User-Agent can impact connections to the phishing site. There may be something the threat actor programmed into their site that prevents specific user agents from connecting.

But what is a user agent? A user agent is a string sent by a web browser, app, or client to a server in an HTTP request header. Think of it as your web browser’s fingerprint when connecting to a web server. I had been trying to connect to these phishing sites through a sandboxed Windows environment all this time.
## The Phishing Site

Since these phishing sites are transported via text message, it makes sense that a threat actor would only expect phone browsers to visit their websites. Also, going directly to the domain doesn’t work. You need a path. Fortunately, this [website](https://smish.report/) provides the latest smishing texts. And I gathered that there was a small pool of paths to follow when visiting a phishing domain. The most common ones were /pay /us /portal. We will visit e-zpassny[.]comloh[.]win/pay for this article.

![](https://miro.medium.com/v2/resize:fit:681/1*336PM9ubk_0BSVVrGk87WQ.png)

The threat actor expects you to enter your phone number, and it will bring you to this page:

![](https://miro.medium.com/v2/resize:fit:700/1*Oz2tO1IF0WYhlz1DFfSQ9A.png)

The victim will then proceed to enter their credit card information. I will review this later, but you cannot enter bogus details here.

![](https://miro.medium.com/v2/resize:fit:700/1*KKS9lg6WL2cGOTByYFbkuQ.png)

There you have it. Hook, line, and sinker. I should note that NY’s real E-ZPass website used to look like this:

![](https://miro.medium.com/v2/resize:fit:639/1*HnaVA3k2y6eCEQSwjsw2Zw.png)

## Network Connections

So now we have successful network connections. What do they say…? Well, it seems our threat actor knows how to obfuscate their trail. One popular method threat actors use to cover their tracks is to appear legitimate using Cloudflare and Google Trust certificates. These IP addresses are Cloudflare.

![](https://miro.medium.com/v2/resize:fit:700/1*M1YUqisIPeEZECDt_t56sg.png)

![](https://miro.medium.com/v2/resize:fit:468/1*Vw1HF7PBN7YGRIy8G2rFlg.png)

Fortunately, the HTTP Header covered in my previous write-up is still valid; I can still see our threat actor’s infrastructure. But we can’t focus on one domain's successful connection. We need to replicate these results. Passing Dragon doesn’t keep their sites up long, leaving room for error. I was able to connect to a different website with slightly different results. e-zpass[.]com-etcicb[.]cc/pay resolving through the IP 49[.]51[.]184[.]123.

![](https://miro.medium.com/v2/resize:fit:700/1*N7R5m3zfGtGMmXcHkLEOTg.png)

Our threat actor abuses Let’s Encrypt as well.

![](https://miro.medium.com/v2/resize:fit:464/1*JrQmgpZGRcecWJjhJvfXUg.png)

So, who is hosting these IPs that provide hosting services to phishing sites? In my research, AS 132203 has been a consistent ASN (autonomous system number). There are others, but this one has been one of the most consistent. Tencent, a Chinese-based conglomerate, hosts this and the other ASNs hosting E-ZPass phishing sites.

## The Code

Someone has to code the website. This means there may be some clues and idiosyncrasies native to the coder. One tool in our arsenal is the view-source function on browsers. This exposes the code on the HTML page. Which, at a glance, is simple:



```
<!DOCTYPE html>  
<html lang="en">  
<head>  
<script type="module" crossorigin src="./assets/fliceXIj.js"></script>  
  
<meta charset="UTF-8">  
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">  
<title id="homeTitle"></title>  
<link rel="icon" id="homeIcon" href="./favicon.png" type="image/svg+xml">  
  
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">  
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">  
<input type="hidden" id="_o_djbempljhcmhlpfacalomonjpalpko" data-inspect-config="3">  
<title></title>  
  
<style>  
.loading-overlay {  
position: fixed;  
top: 0;  
left: 0;  
width: 100%;  
height: 100%;  
background: rgba(255, 255, 255, 1); /* 不透明背景 */  
display: flex;  
align-items: center;  
justify-content: center;  
z-index: 9999;  
}  
  
.loading-gif {  
width: 16px;  
height: 16px;  
}  
  
body {  
padding-top: 0;  
}  
</style>  
  
<script type="module" crossorigin src="./assets/ClRQhJQ2.js"></script>  
<link rel="stylesheet" crossorigin href="./assets/bZRoCO7p.css">  
  
<script type="module">  
import.meta.url; import("_").catch(() => {});  
(async function* () {})().next();  
if (location.protocol === "file:") {  
window.__vite_is_modern_browser = true;  
}  
</script>  
  
<script type="module">  
!function() {  
if (window.__vite_is_modern_browser) return;  
console.warn("vite: loading legacy chunks, syntax error above and the same error below should be ignored");  
var e = document.getElementById("vite-legacy-polyfill"),  
n = document.createElement("script"
```

The HTML page has fewer than 60 lines of code. The Chinese part refers to transparency in RGB. However, two assets within this HTML page need scrutiny: ClRQhJQ2[.]js and bZRoCO7p[.]css. Let’s start with bZRoCO7p[.]css.

CSS controls visual aspects such as colors, fonts, spacing, and positioning of elements. CSS allows developers to separate content (HTML) from presentation, making maintaining and updating designs easier.

After reviewing the CSS code, I found a mix of English and Chinese. One section refers to the App Store and Google Play Store, as we saw on our phishing page.

![](https://miro.medium.com/v2/resize:fit:700/1*HEs7lKQBVCvnilzBEXwOYA.png)

This does not necessarily mean anything. The author of this code may have copied and pasted from a different resource. However, an HTTP address was also hardcoded: hxxx://43[.]153[.]53[.]236.

![](https://miro.medium.com/v2/resize:fit:700/1*LsG4KLM6ENdpj7zkKuDGCg.png)

The HTTP function is down now and has been since December. But before that, it would give 没有找到站点 or “Site not found,” which was likely a ruse. The path was also needed, and enumerating the string on the first part of the path would have been challenging, if not impossible. I found these comments in the second phishing site I visited as well.

![](https://miro.medium.com/v2/resize:fit:634/1*JBiyqbuDkaAhdVJPoARt0A.png)

As for ClRQhJQ2[.]js, we have a problem. The code is heavily obfuscated with references upon references to dynamic functions. The code needs to be analyzed and vetted. It has over 38 thousand lines of code. Upon initial review, the JS is the lifeblood of the phishing site. I can assess that with some certainty because there is a section where we find credit card references.

![](https://miro.medium.com/v2/resize:fit:433/1*QArEsQxG4V0VgyvMXqL5eA.png)

Additionally, we find API calls. But it is a mystery where they are going.

![](https://miro.medium.com/v2/resize:fit:468/1*ESyJ2aPvhw8vzkuXPv_JOA.png)

The JS has encoding and even encryption embedded, making analysis challenging.

## Part Two Conclusion

After trial by fire, we successfully connected to E-ZPass phishing sites through our sandbox. These are the facts I have gathered during this investigation on Passing Dragon:

1. The victim can only connect to these sites through their phone.

2. Passing Dragon is abusing Cloudflare, Google Trust Services, and Let’s Encrypt to lure their victims with “trusted” connections.

3. Passing Dragon uses Tencent to host their infrastructure with a hard-coded IP address owned by Tencent.

4. The CSS and JavaScript code authors are bilingual with coding artifacts in English and Chinese.

5. The authors are sophisticated developers in JavaScript with heavy obfuscation.

Let’s update our Diamond Model to reflect our discoveries.

![](https://miro.medium.com/v2/resize:fit:700/1*N75BEVTpbD0kJgzMtdgP0g.png)