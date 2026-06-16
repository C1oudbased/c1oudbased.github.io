 As established in [Casework Methodology](./casework-methodology.md), investigations are a series of questions and answers. Thankfully there's a pattern and a rhythm to these questions and answers. I find it helps to think of them like flowchart decision trees or fighting game button combos. Things need to be done in the right order and you get faster if you memorize the combinations. This post will explore different investigation techniques I've come across during my time as an analyst as well as some data manipulation techniques that help with investigations.

### Queries
Queries are questions. In our cybersecurity context, a query is specifically a question asked of a database. What querying language in use depends on the platform/software being used at your particular place of work. For the purpose of this post we'll just speak in `SQL` terminology as that's a fairly standard way of querying a database. 

In most roles as an analyst you'll have access to databases containing a specific customer's data. When we use the term "data" here, we're referring to all the information collected by various `agents` installed on hosts in a client environment. `Agent` when in the cybersecurity context, is referring to the _EDR software or service_ running on hosts in an environment that allow for analysts to do things like collect information, isolate hosts, and more! Unprotected hosts in an environment are considered to be "Invisible" to analysts outside of the information we can collect from _around_ the host. We'll discuss this more later. 

In most cases, you'll have access to a panel that allows you to query the environment using a query language. This panel is where we'll ask our questions and fish for answers as efficiently as we can. Let's get an example of how you can turn a customer request for information into valuable data from their database:

Client Request:

> "User Philip Fry clicked on a phishing email today, please take a look at his computer to make sure he didn't infect his host. He uses DESKTOP-PANUCCI and his account name is philipf@planetexpress.com"

This is a perfect example of a client request. Oftentimes they won't include information that might prove valuable to us, but this one does well. Whenever we're handling client requests, we need to validate the _Scope_ of their request. In order to perform an investigation we need to know, at the very least, the involved user/host and the timeframe it occurred in. 

For this scenario, we've identified a timeframe along with the impacted user and host. It occurred in the last 24 hours and it occurred on host "DESKTOP-PANUCCI". Potentially compromised user account is `philipf@planetexpress.com`. Now that we have the information we need to continue, our first query will look something like this:

```SQL
SELECT * FROM Process_History 
WHERE Hostname = "DESKTOP-PANUCCI"
AND Timestamp BETWEEN 'TodaysDate 00:00:00' AND Timestamp 'TodaysDate CurrentTime'
```

Basically, we need to review the process history from the host in order to confirm what, if anything, occurred when the phishing email was interacted with. There's a billion different ways to write the SQL to get the response you need but it all just boils down to whether or not you are able to craft a query that provides the correct data. 
