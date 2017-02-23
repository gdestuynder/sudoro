# sudoro
A "read-only" sudo

What is sudoro?                                                                                                                              
---------------                                                                                                                              
sudoro is a setuid program that provides a "read-only" root-shell.                                                                           
This means it won't be able modify the system state (in theory), for example,                                                                
it won't be able to write files, kill processes, change hostname, etc.                                                                       
                                                                                                                                             
It is provided as a convenience tool for admins, to ensure they do                                                                           
not shoot themselves in the foot while troubleshooting and is not tested                                                                     
as a security tool (though if you test it, let me know how that goes!).                                                                      
**TLDR: Use with caution!**                                                                                                                    
                                                                                                                                             
Example usage                                                                                                                                
-------------                                                                                                                                

```
~/tmp/sudoro ⚡  make && ./sudoro                                                                                                             
gcc sudoro.c -o sudoro -lmount                                                                                                               
sudo chown root:root sudoro                                                                                                                  
sudo chmod ug+s sudoro                                                                                                                       
[root@xps13 sudoro]# kill -9 $BASHPID                                                                                                        
[root@xps13 sudoro]# touch aaa /tmp/aaa                                                                                                      
touch: cannot touch 'aaa': Read-only file system                                                                                             
touch: cannot touch '/tmp/aaa': Read-only file system                                                                                        
[root@xps13 sudoro]# su
su: cannot set groups: Operation not permitted
