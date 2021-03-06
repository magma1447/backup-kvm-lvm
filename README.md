# backup-kvm-lvm
#### Description
Makes a full backup of KVM guests and their filesystems using Borgbackup.
Having support for FSArchiver+SSHFS was the plan, but since I have stopped using that combination myself I don't know if it will happen. It should be fairly easy for someone else to add though. This would be a great alternative for those who don't use Borgbackup.

This isn't heavily tested, but I use it myself to backup 3 KVM hosts with ~10 guests on each. Backups are run weekly, and after over a year in use, I can only say that it seems to work. I have made test restores without any issues as well.

#### Advantages
Since it's filesystem aware specific paths within the virtual machine can be excluded. It's also a lot more effeciant compared to just dd blocks of a device, both in speed and space. Device mappings are created using an LVM snapshot and kpartx.

#### Usage
Place all files in a directory. Verify that the config covers your needs.
Start with: /usr/bin/python backup-kvm-lvm.py -c backup-kvm-lvm.conf /etc/libvirt/qemu/pgc-lua-02.xml
Options can be given either via the conf file, arguments or environment variables. Environment variables are recommended for passwords to keep them hidden.

#### Depends
Depends on ConfigArgParse. If you don't have it you can download the py file from https://github.com/bw2/ConfigArgParse/releases . Just place it in the same folder. Tested with version 0.11.0.

See section Binaries in the conf files for binary depends, like for example kpartx.

#### Cons
* This script is written in Python, which I do not normally work with, therefore the source code looks quite terrible.
* If something goes wrong, the script will write to stderr and just abort. You will need to manually clean up after it, see cleanup section.
* There is no automatic restore, follow the instructions in RESTORE.txt for that.
* Only ext[234] is supported since this has been built to fulfill my own needs only. Adding a new filesystem should normally only need an addition to a whitelist, and testing.
* It only works with guests which has their storage on LVM Logical volumes.
* Does not support LVM usage within the guest itself (ie LVM on LVM).

#### Cleanup
In case the script dies, it will leave potentially leave a few mounts and device mappings. To cleanup, start by unmounting everything mounted in the WorkDir (early in the output). Then lvdisplay |grep Path |grep kvmbackupsnapshot. For each device listed, run kpartx -d -p P <device> and lvremove -f <device>.

