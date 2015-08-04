# BindIP
This program allows you to assign network interfaces (ie "source IP address") for each application in Windows.
You can have one program routed through wifi, another through wired connection, next through a VPN ...

It started as spiritual sucessor of http://old.r1ch.net/stuff/forcebindip/ which is too feature limited and closed sourced,
thus impossible to fix.

Some of the new features are:
* Hooks all winsock APIs, not just selected few (injects itself as WinSock helper filter)
* Proper 64 bit support
* Configuration changes take effect immediately without need to restart the applications
* When interfaces change ip (ie via dhcp) this is reflected immediately too
* GUI

# Usage
![screenshot](http://i.imgur.com/1aXj9pA.png)

In the left list select an application you want to configure, in the right list click on interface to assign
(or 'default route' to remove assignments).

You can set two global options:

*Global Winsock hook* - with this checkbox, all network applications will be affected with settings you configure automatically.
Unfortunately you need admin privileges to do this, but you can still use the second option:

*Add right-click option to shell explorer* - with this enabled, you'll see this when right clicking an application icon shortcut/executable:

![popup](http://i.imgur.com/gfteqV2.png)

You have to run program you want affected by BindIP through this menu item, unless you have enabled *Global Winsock hook*.

Finally, you can just prefix stuff you run on command line with `bindip`, ie

```bash
$ bindip git clone http://some.place/repo
```

Beware that this does not work with ssh git origin (ie when doing git push), as it is ultimately ssh invoked beneath.
In such a case, one needs to modify the underlying command, such as:

```bash
$ export GIT_SSH_COMMAND="bindip ssh"
$ git push
```

# Setting up default interface
When a program has no particular interface selected, ie *(default route')*, system will choose one based on "interface metric".
To change this default, first figure out which interface it actually is:

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
10.0.0.2 is my wired connection, and 192.168.0.2 is VPN. The VPN metric is higher, which means it is not as default (unless explicitly
assigned in BindIP). Wired connection has lowest metric and is thus used as default. To change this arrangement, I can
'View network connections' control panel, find the adapter with that ip (10.0.0.2 in this case):

![metrics](http://i.imgur.com/2oVTnKZ.png)

Click on *Internet protocol version 4 (TCP/IPv4)*, then *Properties*, then *Advanced*, then uncheck *Automatic metric* and put some number in the field.
With manual metrics we can determine the order in which interfaces take precedence as default - the lowest number wins. In this case, metric was changed to 50,
after closing all 3 dialogs we get:

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
And now the VPN takes precedence (is used for everything), because it has lower metric number. Without explicitly setting it,
windows configures metrics automatically, see https://support.microsoft.com/en-us/kb/299540

Caveat: Sometimes, broken VPN software will set two more specific default routes (0.0.0.0 and 128.0.0.0 destinations) as means
to override all other connections regardless of metric. This is harmful kludge or misconfiguration, and should be fixed on the
part of the VPN provider, as users can no longer configure their preferred default route.
