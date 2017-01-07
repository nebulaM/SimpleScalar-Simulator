# Computer Architecture

Modified SimpleScalar simulator

###Usage

1.untar benchmarks.tgz and simcpen411.tgz in a directory of a Linux OS(Bash on Windows 10 not works, it gives compile error).

2.If you run this on an Linux virtual machine and want to edit the files under windows, then add your user to vboxsf group by

```shell
sudo gpasswd -a <username> vboxsf
sudo reboot
```

3.On your local machine, pull this repo to a shared folder between local machine and virtual machine.

4.In virtual machine, put script "run" to the parent directory of your simulator.

5.On your local machine, open "Bash on Ubuntu on Windows" type
```shell
bash cp a1
```

will copy code under folder **a1** to virtual machine and run the simulator. 
