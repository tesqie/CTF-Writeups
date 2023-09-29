---
title: "How to transfer files over Tor"
date: "2022-07-11"
categories: 
  - "tutorials"
tags: 
  - "onionshare"
  - "snap"
  - "tor"
  - "transfer"
coverImage: "k8-0_fkPHulv-M-unsplash-scaled.jpg"
---

First off if you're unfamiliar with Tor. Please visit [https://www.torproject.org/](https://www.torproject.org/) for more information.

We'll be using [OnionShare](https://onionshare.org/) to transfer the files.

I will be using two Linux machines. One running Kali Linux and the other running Ubuntu 20.04.4 LTS.

## Installation

We'll need to install OnionShare on the machine that will be sending the file. In this case, it will be Ubuntu.

I'll be installing OnionShare using the [Snap](https://snapcraft.io/about) package manager.

sudo apt install snapd
systemctl enable --now snapd apparmor

Next, we'll install OnionShare.

sudo snap install onionshare

OnionShare can be used via the GUI. However, I will be using the CLI.

Let's create a new file that will be shared later on.

echo "HELLO" > onionfile

![](images/image-22.png)

Now, all we need to do is start OnionShare and pass the file as the first argument.

onionshare.cli onionfile

[![](images/image-23-1024x966.png)](http://localhost/wordpress/wp-content/uploads/2022/07/image-23.png)

We can now access the file from any other machine through tor using the .onion address with the provided private key.

Go ahead and launch the [Tor browser](https://www.torproject.org/download/) on the Kali pc. Copy/paste the .onion address into the URL.

[![](images/image-24-1024x630.png)](http://localhost/wordpress/wp-content/uploads/2022/07/image-24.png)

Type in the private key.

[![](images/image-25-1024x463.png)](http://localhost/wordpress/wp-content/uploads/2022/07/image-25.png)

Download the file and check its contents.

[![](images/image-26.png)](http://localhost/wordpress/wp-content/uploads/2022/07/image-26.png)

We've successfully transferred the file over Tor!
