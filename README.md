compliance
==========
# Server Hardening

Authors : 
  - Vasanta Koli <http://itsgateway.com>
  - Rahul Patil <http://www.linuxian.com>

![compliance demo](https://raw.github.com/rahulinux/compliance/master/screen-shot1.png)

# Why this script reuqired ?

if you want enhancing server security through a variety of means which results in a much more secure 
server operating environment, then script is useful for you.

you can easily add/modify paramater, in Configuration Section in Script. 


# How it will work ?

It will follow the server hardning process which is mention in "server hardning parameters". 
  - Backup of any configuration file which are going to edit as `config-bkp-current-date`. 
  - Comment old paramaters and apply the new one. 
  - Make configuration file readonly using chattr. 

# Prerequisites

  - The tools/commands are used in script, which almost available in all *nix destro, however you can make sure following list:
    `awk`,`sed`,`mktemp`,`chkconfig`,`stat`.
  - Tested and working in RHEL/CentOS 5.x


# List of Security Rules:


  

  
  
# What else?

If you have any questions or suggestions, you want to share anything else with me, feel free to drop me an e-mail . I appreciate any feedback, including constructive (and polite) criticism, improvement suggestions, questions about usage (if the documentation is unclear).


