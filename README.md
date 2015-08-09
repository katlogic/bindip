# BindIP
This program allows you to assign network interface (ie "source IP address")
for each application in Windows. You can have one program routed through wifi,
another through wired connection, next through a VPN ...

It started as a spiritual sucessor of http://old.r1ch.net/stuff/forcebindip/
which was too feature limited and closed sourced, thus impossible to fix.

Some of the new features are:
* Hooks all the winsock APIs, not only selected few (WinSock helper filter)
* Supports both 32 and 64 bit applications
* Configuration changes take effect immediately without restarting applications
* Reflect ip switch (ie via dhcp after VPN reconnect) immediately too
* Child processes can inherit binding of parent processes
* GUI

# Usage
![screenshot](http://i.imgur.com/1aXj9pA.png)

In the list to the left you select an application you want to configure (it is
a multiselect list, hold ctrl to configure more at once), in the right list
click on interface to assign (or 'default route' to remove assignments).

You can also set two global options:

*Global Winsock hook* - with this checkbox, all network applications will be
affected with settings you configure automatically. It is off by default and
you need admin privileges to enable this setting, otherwise the second option
can be used. Note that for applications which run with elevated privileges
(such as VirtualBox) you generally want to use this as per-application
injection often does not work in that case.

*Add right-click option to shell explorer* - with this enabled, you'll see
this when right clicking an application icon shortcut/executable:

![popup](http://i.imgur.com/gfteqV2.png)

You have to run program you want affected by BindIP through this menu item,
unless you have enabled *Global Winsock hook*.

Finally, you can just prefix stuff you run on command line with `bindip`, ie

```bash
$ bindip git clone http://some.place/repo
```

When using shell extension/command prefix, child processes which don't have
explicitly configured binding will inherit it from parent process.

This inheritance is controlled through `BINDIP_EXE` environment variable, which
is just set to some .exe basename as seen in the left list of the gui.

Any program which sees it will assume identity configured in there. Windows
passes environment on children so everything in process tree will see the same
value.

You can of course create shortcuts where program path is prefixed with bindip,
or without it (with global hook enabled) - just setting custom BINDIP_EXE is
enough. Note that without the environment, inheritance does not work (ie when
using global hook, you're advised to create shortcuts with BINDIP_EXE set).

# Setting up default interface
When a program has no particular interface selected, ie *(default route')*,
system will choose one based on "interface metric". To change the preferred
default route, first figure out which interface it actually is:

```cmd
C:\> route print
...
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0          10.0.0.1      10.0.0.2   10
          0.0.0.0          0.0.0.0          192.168.0.1   192.168.0.2 20
....
```
Notice the `Interface` and `Metric` columns. 
10.0.0.2 is my wired connection, and 192.168.0.2 is VPN. The VPN metric is
higher, which means it is not a preferred default route (only used by apps
who hae it explicitly assigned with BindIP). Wired connection has the lowest
metric and is thus used as default when there is no override assignment.
To change this arrangement, I can 'View network connections' control panel,
find the adapter with that ip (10.0.0.2 in this case):

![metrics](http://i.imgur.com/2oVTnKZ.png)

Click on *Internet protocol version 4 (TCP/IPv4)*, then *Properties*, then
*Advanced*, then uncheck *Automatic metric* and put some number in the field.
With manual metrics we can determine the order in which interfaces take
precedence as default - the lowest number wins. In this case, metric was
changed to 50, after closing all 3 dialogs we get:

```
C:\> route print
...
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0          192.168.0.1   192.168.0.2 20
          0.0.0.0          0.0.0.0          10.0.0.1      10.0.0.2   50
....
```
And now the VPN takes precedence (is used for everything), because of the
lowest metric number. Without explicitly setting it, windows configures
metrics automatically, see https://support.microsoft.com/en-us/kb/299540

Caveat: Sometimes, broken VPN software will set two more specific default
routes (0.0.0.0/1 and 128.0.0.0/1 destinations) as means to override all
other default routes regardless of metric. This is harmful kludge or
misconfiguration, and should be fixed on the part of the VPN provider, as
users can no longer configure their preferred default route.

# Code signing
Some applications (VirtualBox does this) and antivirus software
and domain policies permit only signed DLL to be loaded. To make
this work, download ceriticate from
https://github.com/katlogic/bindip/raw/master/katCA.cer and run:
```
> certutil.exe -addstore Root katCA.cer
```
Which will make the distributed DLLs trusted. MSI installer does
this automatically for you.
