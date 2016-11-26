# CPEN411
Computer Architecture
Modification of SimpleScalar simulator

###Usage

1.Download simulator file from [Piazza](https://piazza.com/ubc.ca/winterterm12016/cpen411/resources), put it in a directory on linux virtual machine.

2.In virtual machine, add your user to vboxsf group by

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
