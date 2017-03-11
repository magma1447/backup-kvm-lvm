# backup-kvm-lvm
#### Description
Makes a full backup of a KVM guests and their filesystems using Borgbackup or FSArchiver. SSHFS can optionally be used for the backup endpoint.

This is still a work in progress, it's not useful yet, though I expect it to be useful within a week.

#### Cons
This script is written in Python, which I do not normally work with, therefore the source code actually looks terrible.
If something goes wrong, the script will write to stderr and just abort. You will need to manually clean up after it.
There is no automatic restore. Though instructions of how to restore will be provided as soon as I have tested it enough.
Not all filesystems are supported. This has been build to fulfill my needs only. Patches are welcome though.
It has only been tested with guests using LVM storage.
