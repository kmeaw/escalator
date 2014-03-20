This is a sudo-like utility to gain other user's privileges
without installing setuid binaries. However, it currently
relies on sudo environment.

== How to use?

* Run `sudo ./escalator` to start server;
* Then call `./escalator command arg1 arg2…` to run command arg1 arg2… in escalated environment.
