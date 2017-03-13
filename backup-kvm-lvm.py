#!/usr/bin/python


# Home: https://github.com/magma1447/backup-kvm-lvm

# TODO
# Implement options to mount/umount a remote server with sshfs (some old related code still exists)
# Add support for sshfs
# Add support for fsarchiver
# Add support for pre-hook, ie mysql lock tables
# Per host/disk overrides for other options, like borg compression
# Color code output? shell stderr in red, shell stdout in grey, python stdout white, python errors (another) red.
# Before making a snapshot, check that there is enough free space in the VG.
# Replace config with https://pypi.python.org/pypi/ConfigArgParse , not included in Debian Stable yet though. I would personally like to override the borg repository.


from __future__ import print_function
import os
import subprocess
import ConfigParser
import sys
import xml.etree.ElementTree
import tempfile
import shutil
import re


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)
	return

def MountSSHFS():
	mountPoint = Config.get('Storage-SSHFS', 'MountPoint')

	if not (os.path.isdir(mountPoint) and os.access(mountPoint, os.W_OK)):
		eprint("SSHFS Local mount point doesn't exist")
		exit(1)
	if os.path.ismount(mountPoint):
		eprint("SSHFS Local mount point is already used")
		exit(1)
	if os.listdir(mountPoint) != []:
		eprint("SSHFS Local mount point is not empty")
		exit(1)

	sshfs = Config.get('Storage-SSHFS', 'sshfs')
	if not (os.path.isfile(sshfs) and os.access(sshfs, os.X_OK)):
		eprint("Access denied on [%s]" % sshfs)
		exit(1)

	print("Mounting sshfs")
	cmd = [
		sshfs,
		'-o',
		'IdentityFile=' + Config.get('Storage-SSHFS', 'Key'),
		Config.get('Storage-SSHFS', 'User') + '@' + Config.get('Storage-SSHFS', 'Host') + ':' + Config.get('Storage-SSHFS', 'RemotePath'), Config.get('Storage-SSHFS', 'MountPoint')
	]
	proc = subprocess.Popen(cmd)
	proc.wait()
	if proc.returncode != 0:
		eprint("Failed to execute [%s]" % sshfs)
		exit(1)
		
		
	return True

def UnmountSSHFS():
	print("Unmounting sshfs")
	proc = subprocess.Popen([Config.get('General', 'fusermount'), '-u', Config.get('Storage-SSHFS', 'MountPoint')])
	proc.wait()

	return True

#def BackupLVMViaSSHFS(Config):
#	print("Backing up LVM config")
#
#	stdout = subprocess.check_output([Config.get('LVM', 'vgcfgbackup'), '-f', Config.get('Storage-SSHFS', 'MountPoint') + 'lvm-%s.conf'])
#
#	stdout = subprocess.check_output([Config.get('LVM', 'pvdisplay')])
#	fp = open(Config.get('Storage-SSHFS', 'MountPoint') + 'pvdisplay.txt', 'w')
#	fp.write(stdout)
#	fp.close()
#
#	stdout = subprocess.check_output([Config.get('LVM', 'lvdisplay')])
#	fp = open(Config.get('Storage-SSHFS', 'MountPoint') + 'lvdisplay.txt', 'w')
#	fp.write(stdout)
#	fp.close()
#
#
#	return True

def GetGuestList():
	guests = []
	if len(sys.argv) > 1:
		for i in xrange(1, len(sys.argv)):
			xml = Config.get('KVM', 'QemuPath') + sys.argv[i]
			if os.path.isfile(xml) and os.access(xml, os.R_OK):
				guests.append(xml)
			else:
				print("WARNING, %s does not exist" % xml)
	else:
		for file in os.listdir(Config.get('KVM', 'QemuPath')):
			if file.endswith(".xml"):
				guests.append(file)
	
	return guests

def GetGuestConfigs():
	guestConfigs = []

	for guest in guests:
		x = xml.etree.ElementTree.parse(guest).getroot()
		guestName = x.find("./name").text
		guestConfig = { "xml": guest, "name": guestName, "disks": {} }

		disks = x.findall("./devices/disk")
		for disk in disks:
			if disk.attrib['device'] == 'cdrom':
				continue
			elif disk.attrib['device'] == 'disk':
				sourceDev = disk.find("./source").attrib['dev']
				targetDev = disk.find("./target").attrib['dev']
				proc = subprocess.Popen([Config.get('LVM', 'lvs'), '--noheadings', sourceDev], stdout=FNULL)
				r = proc.wait()
				if r != 0:
					eprint("Guest %s has a disk that is not a logical volume, %s" % guest, sourceDev)
					exit(1)
				guestConfig["disks"][targetDev] = sourceDev
				
				
			else:
				eprint("Unknown device type %s" % disk.attrib['device'])
				exit(1)
		guestConfigs.append(guestConfig)

	return guestConfigs

def CreateLVMSnapshot(sourceDevice):
	snapshotName = os.path.basename(sourceDevice) + Config.get('LVM', 'SnapshotSuffix')
	proc = subprocess.Popen([Config.get('LVM', 'lvcreate'), '-L' + Config.get('LVM', 'SnapshotSize'), '-s', '-n', snapshotName, sourceDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to create snapshot of %s" % sourceDevice)
		exit(1)

	# Find the VG name, use the original name. The snapshot might not exist in the path used.
	VG = None
	stdout = subprocess.check_output([Config.get('LVM', 'lvdisplay'), sourceDevice])
	stdout = stdout.split("\n")
	for line in stdout:
		line = line.strip()
		m = re.match("^VG Name\s+(.*)$", line)
		if m != None:
			VG = m.groups()[0]
			break

	if VG == None:
		eprint("Failed to find VG for snapshot of %s" % sourceDevice)
		exit(1)
	
	snapshotDevice = "/dev/" + VG + "/" + snapshotName

	return snapshotDevice

def RemoveLVMSnapshot(snapshotDevice):
	proc = subprocess.Popen([Config.get('LVM', 'lvremove'), '-f', snapshotDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to remove snapshot %s" % snapshotDevice)
		exit(1)

def CreatePartitionMappings(snapshotDevice):
	#kpartx -av -p P -s /dev/pgc-kvm-03-SAS600/pgc-http-01-kvmbackupsnapshot
	stdout = subprocess.check_output([Config.get('General', 'kpartx'), '-a', '-v', '-p', 'P', '-s', snapshotDevice])
	devices = []
	for line in stdout.splitlines():
		devices.append(line.split()[2])
	return devices

def RemovePartitionMappings(snapshotDevice):
	#kpartx -d -p P /dev/pgc-kvm-03-SAS600/pgc-http-01-kvmbackupsnapshot
	proc = subprocess.Popen([Config.get('General', 'kpartx'), '-d', '-p', 'P', snapshotDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to remove partition mappings for %s" % snapshotDevice)
		exit(1)

def GetValueOfTagFromDevice(device, tag):
	stdout = subprocess.check_output([Config.get('General', 'blkid'), '-o', 'value', '-s', tag, device])
	return stdout.strip()

def SaveLVDisplay(sourceDevice, targetDevice):
	# lvdisplay, needed to recreate the logical volume
	filename = 'disks/' + targetDevice + '.lvdisplay'
	stdout = subprocess.check_output([Config.get('LVM', 'lvdisplay'), sourceDevice])
	fp = open(filename, 'w')
	fp.write(stdout)
	fp.close()
	filesCreated.append(filename)

def BackupPartitionTable(sourceDevice, targetDevice):
	# sfdisk, for recreating the partition table
	filename = 'disks/' + targetDevice + '.sfdisk'
	stdout = subprocess.check_output([Config.get('General', 'sfdisk'), '-d', sourceDevice])
	fp = open(filename, 'w')
	fp.write(stdout)
	fp.close()
	filesCreated.append(filename)

	# fdisk -l, most likely not needed, but gives the user an easy glance
	filename = 'disks/' + targetDevice + '.fdisk'
	stdout = subprocess.check_output([Config.get('General', 'fdisk'), '-l', sourceDevice])
	fp = open(filename, 'w')
	fp.write(stdout)
	fp.close()
	filesCreated.append(filename)

def BackupMBR(sourceDevice, targetDevice):
	# mbr
	filename = 'disks/' + targetDevice + '.mbr'
	proc = subprocess.Popen([Config.get('General', 'dd'), 'if=' + sourceDevice, 'bs=512', 'count=1', 'of=' + filename])
	proc.wait()
	filesCreated.append(filename)

def BackupUUID(targetDevice, p):
	uuid = GetValueOfTagFromDevice('/dev/mapper/' + partitionDevice , 'UUID')
	filename = 'disks/' + targetDevice + '/' + p + '.UUID'
	fp = open(filename, 'w')
	fp.write(uuid)
	fp.close()
	filesCreated.append(filename)

def Borgbackup(name):
	print("Starting backup (borgbackup)")
	borgEnv = os.environ.copy()
	borgEnv["BORG_RSH"] = Config.get('Method:Borgbackup', 'RSH')
	borgEnv["BORG_PASSPHRASE"] = Config.get('Method:Borgbackup', 'PASSPHRASE')
	cmd = [
		Config.get('Method:Borgbackup', 'binary'),
		'create',
		'--numeric-owner',
		'--lock-wait',
		Config.get('Method:Borgbackup', 'LockWait'),
		'--compression',
		Config.get('Method:Borgbackup', 'Compression'),
		Config.get('Method:Borgbackup', 'Repository') + '::' + name + '_{now}',
		'.'
	]
	proc = subprocess.Popen(cmd, env=borgEnv)
	proc.wait()
	if proc.returncode != 0:
		eprint("borgbackup create failed")
		exit(1)

	print("Running a repository check")
	borgEnv = os.environ.copy()
	borgEnv["BORG_RSH"] = Config.get('Method:Borgbackup', 'RSH')
	borgEnv["BORG_PASSPHRASE"] = Config.get('Method:Borgbackup', 'PASSPHRASE')
	cmd = [
		Config.get('Method:Borgbackup', 'binary'),
		'check',
		'--lock-wait',
		Config.get('Method:Borgbackup', 'LockWait'),
		'--last',
		Config.get('Method:Borgbackup', 'CheckLast'),
		Config.get('Method:Borgbackup', 'Repository')
	]
	proc = subprocess.Popen(cmd, env=borgEnv)
	proc.wait()
	if proc.returncode != 0:
		eprint("borgbackup check failed")
		exit(1)
	
	print("Borgbackup done")



confFile = 'backup-kvm-lvm.conf'
FNULL = open(os.devnull, 'w')


print("Reading conf [%s]" % confFile)
if not (os.path.isfile(confFile) and os.access(confFile, os.R_OK)):
	exit("Can not find " + confFile + "\n");
Config = ConfigParser.ConfigParser()
Config.read(confFile)


if Config.getboolean('General', 'RequireRoot'):
	if os.geteuid() != 0:
		exit("You need to have root privileges to run this script.\n");

guests = GetGuestList()
guestConfigs = GetGuestConfigs()



tmpDir = tempfile.mkdtemp('', 'kvm-backup_', Config.get('Backup', 'TmpDir')) + '/'
os.chdir(tmpDir)
print("Current workdir: %s" % tmpDir)
for guest in guestConfigs:
	if Config.has_option("Guest:" + guest['name'], 'ignore') and Config.getboolean("Guest:" + guest['name'], 'ignore') == True:
		print("Skipping guest %s, ignored in config" % guest['name'])
		continue

	print("Preparing backup of %s" % guest['name'])
	filesCreated = []
	directoriesCreated = []

	os.mkdir(guest['name'])
	os.chdir(guest['name'])


	# Check the config if a host section exists where some devices has been excluded
	excludeFilesOnSourceDevices = []
	if Config.has_option("Guest:" + guest['name'], 'excludeFilesOnSourceDevices'):
		excludeFilesOnSourceDevices = Config.get("Guest:" + guest['name'], 'excludeFilesOnSourceDevices').split(':')


	# Add a copy of the libvirt xml
	shutil.copy(guest['xml'], '.')
	filesCreated.append( os.path.basename(guest['xml']) )

	os.mkdir('disks')
	directoriesCreated.append('disks')
	LVMsnapshots = []
	mountPoints = []
	for targetDevice, sourceDevice in guest['disks'].iteritems():
		print("Device %s => %s" % (sourceDevice, targetDevice))

		os.mkdir('disks/' + targetDevice)
		directoriesCreated.append('disks/' + targetDevice)

		snapshotDevice = CreateLVMSnapshot(sourceDevice)
		LVMsnapshots.append(snapshotDevice)

		SaveLVDisplay(sourceDevice, targetDevice)

		pttype = GetValueOfTagFromDevice(snapshotDevice, 'PTTYPE')
		if pttype == 'dos':
			print("Device seems to be a disk in the guest")

			BackupPartitionTable(snapshotDevice, targetDevice)
			BackupMBR(snapshotDevice, targetDevice)

			partitionDevices = CreatePartitionMappings(snapshotDevice)
			for partitionDevice in partitionDevices:
				m = re.search("P\d+$", partitionDevice)
				p = m.group(0)
				
				BackupUUID(targetDevice, p)

				partitionPttype = GetValueOfTagFromDevice('/dev/mapper/' + partitionDevice , 'PTTYPE')
				partitionType = GetValueOfTagFromDevice('/dev/mapper/' + partitionDevice , 'TYPE')
				if partitionType == 'ext2' or partitionType == 'ext3' or partitionType == 'ext4':
					print("Partition %s has a readable filesystem (%s)" % (partitionDevice, partitionType))
					os.mkdir('disks/' + targetDevice + '/' + p)
					directoriesCreated.append('disks/' + targetDevice + '/' + p)

					# Store a 'tune2fs -l'
					filename = 'disks/' + targetDevice + '/' + p + '.ext'
					stdout = subprocess.check_output([Config.get('General', 'tune2fs'), '-l', '/dev/mapper/' + partitionDevice])
					fp = open(filename, 'w')
					fp.write(stdout)
					fp.close()
					filesCreated.append(filename)


					if sourceDevice in excludeFilesOnSourceDevices:
						print("Not mounting device, listed in excludeFilesOnSourceDevices")
					else:
						proc = subprocess.Popen([Config.get('General', 'mount'), '-o', 'ro', '/dev/mapper/' + partitionDevice, 'disks/' + targetDevice + '/' + p])
						proc.wait()
						if proc.returncode != 0:
							eprint("Failed to mount %s" % partitionDevice)
							exit(1)
						mountPoints.append('disks/' + targetDevice + '/' + p)
					
				elif partitionType == 'swap':
					print("Skipping swap partition")
				elif partitionPttype == 'dos':
					print("Found dos partition on the disk, assume it's not needed")
				else:
					eprint("Unknown FS found on snapshot of device %s, %s" % (sourceDevice, partitionDevice))
					exit(1)

		else:
			print("PTTYPE of device isn't dos. Assuming the device is a partition of some kind")
			BackupPartitionTable(snapshotDevice, targetDevice)
			# It's not likely that there actually is a MBR on this device, but let's be safe.
			BackupMBR(snapshotDevice, targetDevice)


			partitionType = GetValueOfTagFromDevice(snapshotDevice, 'TYPE')
			if partitionType == 'ext2' or partitionType == 'ext3' or partitionType == 'ext4':
				print("Snapshot of device %s has a readable filesystem (%s)" % (sourceDevice, partitionType))
				if sourceDevice in excludeFilesOnSourceDevices:
					print("Not mounting device, listed in excludeFilesOnSourceDevices")
				else:
					proc = subprocess.Popen([Config.get('General', 'mount'), '-o', 'ro', snapshotDevice, 'disks/' + targetDevice])
					proc.wait()
					if proc.returncode != 0:
						eprint("Failed to mount snapshot of %s" % sourceDevice)
						exit(1)
					mountPoints.append('disks/' + targetDevice)



			elif partitionType == 'swap':
				print("Skipping swap partition")
			elif partitionPttype == 'dos':
				print("Found dos partition on the disk, assume it's not needed")
			else:
				eprint("Unknown FS found on snapshot of device %s" % sourceDevice)
				exit(1)
			
			


	if Config.get('Backup', 'Method') == 'Borgbackup':
		Borgbackup(guest['name'])
	else:
		eprint("Unknown backup method")
		exit(1)

	


	print("Starting to cleanup after %s" % guest['name'])
	for mountPoint in mountPoints:
		proc = subprocess.Popen([Config.get('General', 'umount'), mountPoint])
		proc.wait()
		if proc.returncode != 0:
			eprint("Failed to umount %s" % mountPoint)
			exit(1)
			
	for LVMsnapshot in LVMsnapshots:
		RemovePartitionMappings(LVMsnapshot)
		RemoveLVMSnapshot(LVMsnapshot)

	for file in reversed(filesCreated):
		os.remove(file)
	for directory in reversed(directoriesCreated):
		os.rmdir(directory)

	os.chdir(tmpDir)
	os.rmdir(guest['name'])

	print("Done with guest %s" % guest)
	print('')

os.rmdir(tmpDir)

print("BACKUP SUCCESSFUL")
exit(0)

if Config.get('Storage', 'Method') == 'sshfs':
	MountSSHFS()



	UnmountSSHFS()

else:
	eprint("Unknown storage method")
	exit(1)


