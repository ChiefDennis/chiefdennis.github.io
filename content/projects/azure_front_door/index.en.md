+++
title = "Configure and test Azure Front Door automatic failover"
date = 2024-04-22T08:43:16+01:00
draft = true
description = ""
slug = ""
authors = ["Dennis Drebitca"]
tags = ["Azure","Web Applications","Azure Front Door"]
categories = []
externalLink = ""
series = ["Microsoft Azure", "Azure Front Door"]
+++

In this exercise, we will set up an Azure Front Door configuration that pools two instances of a web application that runs in different Azure regions. This configuration directs traffic to the nearest site that runs the application. Azure Front Door continuously monitors the web application. We will demonstrate automatic failover to the next available site when the nearest site is unavailable.

We will follow these steps:

1. Create two instances of a web app
2. Create a Front Door for the application
3. Test Azure Front Door Automatic Failover
4. Delete the unnecesary resources





