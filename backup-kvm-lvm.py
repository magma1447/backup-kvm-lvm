#!/usr/bin/python


#####
# github link
# by GZC
#####


from __future__ import print_function
import os
import subprocess
import ConfigParser
import sys
import xml.etree.ElementTree
import tempfile
#from shutil import copyfile
import shutil
import re
import time # debug


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
	proc = subprocess.Popen([Config.get('LVM', 'lvcreate'), '-L' + Config.get('LVM', 'SnapshotSize'), '-s', '-n', os.path.basename(sourceDevice) + Config.get('LVM', 'SnapshotSuffix'), sourceDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to create snapshot of %s" % sourceDevice)
		exit(1)

def RemoveLVMSnapshot(sourceDevice):
	proc = subprocess.Popen([Config.get('LVM', 'lvremove'), '-f', sourceDevice + Config.get('LVM', 'SnapshotSuffix')])
        r = proc.wait()
	if r != 0:
		eprint("Failed to remove snapshot of %s" % sourceDevice)
		exit(1)

def CreatePartitionMappings(sourceDevice):
	#kpartx -av -p P -s /dev/pgc-kvm-03-SAS600/pgc-http-01-kvmbackupsnapshot
	stdout = subprocess.check_output([Config.get('General', 'kpartx'), '-a', '-v', '-p', 'P', '-s', sourceDevice + Config.get('LVM', 'SnapshotSuffix')])
	devices = []
	for line in stdout.splitlines():
		devices.append(line.split()[2])
	return devices

def RemovePartitionMappings(sourceDevice):
	#kpartx -d -p P /dev/pgc-kvm-03-SAS600/pgc-http-01-kvmbackupsnapshot
	proc = subprocess.Popen([Config.get('General', 'kpartx'), '-d', '-p', 'P', sourceDevice + Config.get('LVM', 'SnapshotSuffix')])
        r = proc.wait()
	if r != 0:
		eprint("Failed to remove partition mappings for %s" % sourceDevice)
		exit(1)

def GetValueOfTagFromDevice(device, tag):
	stdout = subprocess.check_output([Config.get('General', 'blkid'), '-o', 'value', '-s', tag, device])
	return stdout.strip()




confFile = 'backup-kvm.conf'
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
	print("Preparing backup of %s" % guest['name'])
	filesCreated = []
	directoriesCreated = []

	os.mkdir(guest['name'])
	os.chdir(guest['name'])


	# Add a copy of the libvirt xml
	shutil.copy(guest['xml'], '.')
	filesCreated.append( os.path.basename(guest['xml']) )

	os.mkdir('disks')
	directoriesCreated.append('disks')
	LVMsnapshots = []
	mountPoints = []
	for targetDevice, sourceDevice in guest['disks'].iteritems():
		print("Device %s => %s" % (sourceDevice, targetDevice))
		CreateLVMSnapshot(sourceDevice)
		LVMsnapshots.append(sourceDevice)
		pttype = GetValueOfTagFromDevice(sourceDevice, 'PTTYPE')
		if pttype == 'dos':
			print("Device seems to be a disk in the guest")
			os.mkdir('disks/' + targetDevice)
			directoriesCreated.append('disks/' + targetDevice)

			# TODO sfdisk, mbr, fdisk -l, lvdisplay device

			partitionDevices = CreatePartitionMappings(sourceDevice)
			for partitionDevice in partitionDevices:
				partitionPttype = GetValueOfTagFromDevice('/dev/mapper/' + partitionDevice , 'PTTYPE')
				partitionType = GetValueOfTagFromDevice('/dev/mapper/' + partitionDevice , 'TYPE')
				if partitionType == 'ext2' or partitionType == 'ext3' or partitionType == 'ext4':
					print("Partition %s has a readable filesystem (%s)" % (partitionDevice, partitionType))
					m = re.search("P\d+$", partitionDevice)
					p = m.group(0)
					os.mkdir('disks/' + targetDevice + '/' + p)
					directoriesCreated.append('disks/' + targetDevice + '/' + p)

					proc = subprocess.Popen([Config.get('General', 'mount'), '/dev/mapper/' + partitionDevice, 'disks/' + targetDevice + '/' + p])
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
					eprint("Unknown FS found on device %s, %s" % (sourceDevice, partitionDevice))
					exit(1)

		else:
			print("PTTYPE of device isn't dos. Assuming the device is a partition of some kind")
			# TODO sfdisk, mbr, fdisk -l, lvdisplay device


			partitionType = GetValueOfTagFromDevice(sourceDevice, 'TYPE')
			if partitionType == 'ext2' or partitionType == 'ext3' or partitionType == 'ext4':
				print("Device %s has a readable filesystem (%s)" % (sourceDevice, partitionType))
				proc = subprocess.Popen([Config.get('General', 'mount'), sourceDevice, 'disks/' + targetDevice])
				proc.wait()
				if proc.returncode != 0:
					eprint("Failed to mount %s" % sourceDevice)
					exit(1)
				mountPoints.append('disks/' + targetDevice)



			elif partitionType == 'swap':
				print("Skipping swap partition")
			elif partitionPttype == 'dos':
				print("Found dos partition on the disk, assume it's not needed")
			else:
				eprint("Unknown FS found on device %s" % sourceDevice)
				exit(1)
			
			


	time.sleep(2)
	# TODO actually create a backup here. Either with borgbackup or fsarchiver


	print("Starting to cleanup after %s" % guest)
	for mountPoint in mountPoints:
		proc = subprocess.Popen([Config.get('General', 'umount'), mountPoint])
		proc.wait()
		if proc.returncode != 0:
			eprint("Failed to umount %s" % mountPoint)
			exit(1)
			
	for targetDevice, sourceDevice in guest['disks'].iteritems():
		RemovePartitionMappings(sourceDevice)

	for LVMsnapshot in LVMsnapshots:
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


