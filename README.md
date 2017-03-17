# sudoro
A "read-only" sudo

What is sudoro?
---------------
sudoro is a setuid program that provides a "read-only" root-shell.
This means it won't be able modify the system state (in theory), for example,
it won't be able to write files, kill processes, change hostname, etc.
You *will* be able to read all files, and diagnose most things, and thus if 
your sole access is via sudoro, you will be able to exfiltrate *any* data on 
the system.

It is provided as a convenience tool for admins, to ensure they do
not shoot themselves in the foot while troubleshooting and is not tested
as a security tool (though if you test it, let me know how that goes!).
**TLDR: Use with caution!**

Example usage
-------------

```
~/tmp/sudoro ⚡  make && ./sudoro
gcc sudoro.c -o sudoro -lmount
sudo chown root:wheel sudoro
sudo chmod u+s sudoro
sudo chmod g+x sudoro
[root@xps13 sudoro]# kill -9 $BASHPID
[root@xps13 sudoro]# touch aaa /tmp/aaa
touch: cannot touch 'aaa': Read-only file system
touch: cannot touch '/tmp/aaa': Read-only file system
[root@xps13 sudoro]# su
su: cannot set groups: Operation not permitted
[root@xps13 sudoro]# reboot
Failed to write to /dev/initctl: Operation not permitted
Failed to talk to init daemon.
```

"Security" considerations
-------------------------

Sudoro will only allow users of the group it's set to - to execute itself. In 
addition to that, sudoro only makes sense when the binary is marked with setuid
 root. Example:

```
# chown root:wheel sudoro
# chmod u+s sudoro
# chmod ug+x sudoro
# exit
$ id
uid=1000(kang)... groups=99(wheel)
$ ./sudoro /bin/cat /etc/shadow
root:x:17203::::::
bin:x:14871::::::
....
```

You can compile sudoro with ALLOW_TMP_WRITE=1 (default) which will allow writes 
to /tmp so that programs don't complain too much. These are namespaced mounts
so won't affect the host filesystem, but since it will no longer deny the
write() systemcall, it is potentially not as safe.  Note that this will mask
the host's /tmp directory.

"FAQ"
-----

- Does this drop capabilities?
Yes, except for `CAP_DAC_READ_SEARCH`, `CAP_NET_RAW`.

- Does it keep uid 0/ root?
Yes.

- Does it use namespaces ("container?!")?
Yes. mount, ipc, pid, uts, cgroup are unshared.

- Does it use seccomp ("sandbox?!")?
Yes, it use seccomp to protect against some additional things.

- Can I put this on a guest shell ssh-accessible to the internet and nothing bad will happen?
Absolu..err. That seems like a terrible idea, but I'd like to see how many
stupid things I forgot that would let you in, so please go ahead, let me know
how that goes! ;-)

- Did :atoll give you this idea?
Yes!
