#!/usr/bin/python


# Home: https://github.com/magma1447/backup-kvm-lvm

# TODO
# Implement options to mount/umount a remote server with sshfs (some old related code still exists)
# Add support for fsarchiver
# Add support for pre-hook, ie mysql lock tables
# Per host/disk overrides for other options, like borg compression. How?
# Color code output? shell stderr in red, shell stdout in grey, python stdout white, python errors (another) red.
# Before making a snapshot, check that there is enough free space in the VG.
# When backing up multiple at once we are running check over and over on the same hosts. We need to move the check. check-last will then potentially be too small.
# For all binary path options, check that they exist and that we can read/execute them.


from __future__ import print_function
import os
import subprocess
import configargparse
import sys
import xml.etree.ElementTree
import tempfile
import shutil
import re


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)
	return

#def MountSSHFS():
#	mountPoint = Config.get('Storage-SSHFS', 'MountPoint')
#
#	if not (os.path.isdir(mountPoint) and os.access(mountPoint, os.W_OK)):
#		eprint("SSHFS Local mount point doesn't exist")
#		exit(1)
#	if os.path.ismount(mountPoint):
#		eprint("SSHFS Local mount point is already used")
#		exit(1)
#	if os.listdir(mountPoint) != []:
#		eprint("SSHFS Local mount point is not empty")
#		exit(1)
#
#	sshfs = Config.get('Storage-SSHFS', 'sshfs')
#	if not (os.path.isfile(sshfs) and os.access(sshfs, os.X_OK)):
#		eprint("Access denied on [%s]" % sshfs)
#		exit(1)
#
#	print("Mounting sshfs")
#	cmd = [
#		sshfs,
#		'-o',
#		'IdentityFile=' + Config.get('Storage-SSHFS', 'Key'),
#		Config.get('Storage-SSHFS', 'User') + '@' + Config.get('Storage-SSHFS', 'Host') + ':' + Config.get('Storage-SSHFS', 'RemotePath'), Config.get('Storage-SSHFS', 'MountPoint')
#	]
#	proc = subprocess.Popen(cmd)
#	proc.wait()
#	if proc.returncode != 0:
#		eprint("Failed to execute [%s]" % sshfs)
#		exit(1)
#		
#		
#	return True

#def UnmountSSHFS():
#	print("Unmounting sshfs")
#	proc = subprocess.Popen([Config.get('General', 'fusermount'), '-u', Config.get('Storage-SSHFS', 'MountPoint')])
#	proc.wait()
#
#	return True

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

def VerifyGuestList():
	for file in options.xml:
		if not os.path.isfile(file) or not os.access(file, os.R_OK):
			eprint("Access denied to %s" % file)
			exit(1)

def GetGuestConfigs():
	guestConfigs = []

	for guest in options.xml:
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
				proc = subprocess.Popen([options.binary_lvs, '--noheadings', sourceDev], stdout=FNULL)
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
	snapshotName = os.path.basename(sourceDevice) + options.lvm_snapshot_suffix
	proc = subprocess.Popen([options.binary_lvcreate, '-L' + options.lvm_snapshot_size, '-s', '-n', snapshotName, sourceDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to create snapshot of %s" % sourceDevice)
		exit(1)

	# Find the VG name, use the original name. The snapshot might not exist in the path used.
	VG = None
	stdout = subprocess.check_output([options.binary_lvdisplay, sourceDevice])
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
	proc = subprocess.Popen([options.binary_lvremove, '-f', snapshotDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to remove snapshot %s" % snapshotDevice)
		exit(1)

def CreatePartitionMappings(snapshotDevice):
	#kpartx -av -p P -s /dev/pgc-kvm-03-SAS600/pgc-http-01-kvmbackupsnapshot
	stdout = subprocess.check_output([options.binary_kpartx, '-a', '-v', '-p', 'P', '-s', snapshotDevice])
	devices = []
	for line in stdout.splitlines():
		devices.append(line.split()[2])
	return devices

def RemovePartitionMappings(snapshotDevice):
	#kpartx -d -p P /dev/pgc-kvm-03-SAS600/pgc-http-01-kvmbackupsnapshot
	proc = subprocess.Popen([options.binary_kpartx, '-d', '-p', 'P', snapshotDevice])
        r = proc.wait()
	if r != 0:
		eprint("Failed to remove partition mappings for %s" % snapshotDevice)
		exit(1)

def GetValueOfTagFromDevice(device, tag):
	stdout = subprocess.check_output([options.binary_blkid, '-o', 'value', '-s', tag, device])
	return stdout.strip()

def SaveLVDisplay(sourceDevice, targetDevice):
	# lvdisplay, needed to recreate the logical volume
	filename = 'disks/' + targetDevice + '.lvdisplay'
	stdout = subprocess.check_output([options.binary_lvdisplay, sourceDevice])
	fp = open(filename, 'w')
	fp.write(stdout)
	fp.close()
	filesCreated.append(filename)

def BackupPartitionTable(sourceDevice, targetDevice):
	# sfdisk, for recreating the partition table
	filename = 'disks/' + targetDevice + '.sfdisk'
	try:
		stdout = subprocess.check_output([options.binary_sfdisk, '-d', sourceDevice])
		fp = open(filename, 'w')
		fp.write(stdout)
		fp.close()
		filesCreated.append(filename)
	except Exception:
		pass

	# fdisk -l, most likely not needed, but gives the user an easy glance
	filename = 'disks/' + targetDevice + '.fdisk'
	stdout = subprocess.check_output([options.binary_fdisk, '-l', sourceDevice])
	fp = open(filename, 'w')
	fp.write(stdout)
	fp.close()
	filesCreated.append(filename)

def BackupMBR(sourceDevice, targetDevice):
	# mbr
	filename = 'disks/' + targetDevice + '.mbr'
	proc = subprocess.Popen([options.binary_dd, 'if=' + sourceDevice, 'bs=512', 'count=1', 'of=' + filename])
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
	print("Starting backup (borg)")

	borgEnv = os.environ.copy()
	if options.borg_RSH is not None:
		borgEnv["BORG_RSH"] = options.borg_RSH
	if options.borg_PASSPHRASE is not None:
		borgEnv["BORG_PASSPHRASE"] = options.borg_PASSPHRASE

	cmd = [
		options.binary_borg,
		'create',
		'--numeric-owner',
	]
	if options.borg_lock_wait is not None:
		cmd.extend([
			'--lock-wait',
			options.borg_lock_wait
		])
	if options.borg_compression is not None:
		cmd.extend([
			'--compression',
			options.borg_compression
		])
	cmd.extend([
		options.borg_repository + '::' + name + '_{now}', '.' 
	])

	proc = subprocess.Popen(cmd, env=borgEnv)
	proc.wait()
	if proc.returncode != 0:
		eprint("borg create failed")
		exit(1)

	print("Borgbackup done")



FNULL = open(os.devnull, 'w')


p = configargparse.ArgParser(default_config_files = [ '/etc/backup-kvm-lvm.conf', '~/.backup-kvm-lvm.conf', 'backup-kvm-lvm.conf' ])
p.add('-c', '--config', is_config_file=True, help='config file path')
p.add('--require-root', action='store_true', default=True, help='abort if not root')
p.add('-d', '--tmp-dir', default='/tmp/', help='directory where the temporary workdir will be created')
p.add('-m', '--method', default='borg', help='backup method, currently only borg')
p.add('--binary-fusermount', default='/bin/fusermount', help='path to fusermount')
p.add('--binary-blkid', default='/sbin/blkid', help='path to blkid')
p.add('--binary-kpartx', default='/sbin/kpartx', help='path to kpartx')
p.add('--binary-sfdisk', default='/sbin/sfdisk', help='path to sfdisk')
p.add('--binary-mount', default='/bin/mount', help='path to mount')
p.add('--binary-umount', default='/bin/umount', help='path to umount')
p.add('--binary-dd', default='/bin/dd', help='path to dd')
p.add('--binary-fdisk', default='/sbin/fdisk', help='path to fdisk')
p.add('--binary-tune2fs', default='/sbin/tune2fs', help='path to tune2fs')
p.add('--binary-lvs', default='/sbin/lvs', help='path to lvs')
p.add('--binary-lvcreate', default='/sbin/lvcreate', help='path to lvcreate')
p.add('--binary-lvremove', default='/sbin/lvremove', help='path to lvremove')
p.add('--binary-lvdisplay', default='/sbin/lvdisplay', help='path to lvdisplay')
p.add('-L', '--lvm-snapshot-size', default='10G', help='size of LVM snapshot')
p.add('-S', '--lvm-snapshot-suffix', default='_kvmbackupsnapshot', help='LVM snapshot suffix')
p.add('--binary-borg', default='/usr/local/bin/borg', help='path to borg')
p.add('--borg-RSH', default=None, help='RSH environment variable for borg')
p.add('--borg-PASSPHRASE', default=None, help='PASSPHRASE environment variable for borg')
p.add('--borg-compression', default=None, help='borg compression')
p.add('--borg-lock-wait', default=None, help='borg lock-wait')
# TODO break up repository in user, host, path
p.add('--borg-repository', required=True, help='borg repository')
# TODO Add option to only check with the same host
p.add('--borg-check-last', default=None, help='borg check-last')
p.add('--ignore-files-on-source-devices', default=[], nargs='*', help='don\'t backup files on these source devices, but do backup the metadata')
p.add('--ignore-guests', default=[], nargs='*', help='ignore these guests')
p.add('xml', nargs='+', help='guest xml files')
options = p.parse_args()



if options.require_root and os.geteuid() != 0:
	eprint("You need to have root privileges to run this script.\n");
	exit(1)


VerifyGuestList()
guestConfigs = GetGuestConfigs()

tmpDir = tempfile.mkdtemp('', 'kvm-backup_', options.tmp_dir) + '/'
os.chdir(tmpDir)
print("Current workdir: %s" % tmpDir)
for guest in guestConfigs:
	if guest['name'] in options.ignore_guests:
		print("Skipping guest %s, ignored in config" % guest['name'])
		continue

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

		os.mkdir('disks/' + targetDevice)
		directoriesCreated.append('disks/' + targetDevice)

		snapshotDevice = CreateLVMSnapshot(sourceDevice)
		print("Snapshoted %s => %s" % (sourceDevice, snapshotDevice))
		LVMsnapshots.append(snapshotDevice)

		SaveLVDisplay(sourceDevice, targetDevice)

		pttype = GetValueOfTagFromDevice(snapshotDevice, 'PTTYPE')
		if pttype == 'dos' or pttype == 'gpt':
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
					stdout = subprocess.check_output([options.binary_tune2fs, '-l', '/dev/mapper/' + partitionDevice])
					fp = open(filename, 'w')
					fp.write(stdout)
					fp.close()
					filesCreated.append(filename)


					if sourceDevice in options.ignore_files_on_source_devices:
						print("Not mounting device, listed in ignore-files-on-source-devices")
					else:
						proc = subprocess.Popen([options.binary_mount, '-o', 'ro', '/dev/mapper/' + partitionDevice, 'disks/' + targetDevice + '/' + p])
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
				if sourceDevice in options.ignore_files_on_source_devices:
					print("Not mounting device, listed in ignore-files-on-source-devices")
				else:
					proc = subprocess.Popen([options.binary_mount, '-o', 'ro', snapshotDevice, 'disks/' + targetDevice])
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
			
			


	if options.method == 'borg':
		Borgbackup(guest['name'])
	else:
		eprint("Unknown backup method")
		exit(1)

	


	print("Starting to cleanup after %s" % guest['name'])
	for mountPoint in mountPoints:
		proc = subprocess.Popen([options.binary_umount, mountPoint])
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



if options.method == 'borg' and options.borg_check_last is not None:
	print("Running a repository check")
	if len(guestConfigs) > options.borg_check_last:
		print("Warning, backed up more guests than we will check (%d > %d)." % (len(guestConfigs), options.borg_check_last))

	borgEnv = os.environ.copy()
	if options.borg_RSH is not None:
		borgEnv["BORG_RSH"] = options.borg_RSH
	if options.borg_PASSPHRASE is not None:
		borgEnv["BORG_PASSPHRASE"] = options.borg_PASSPHRASE

	cmd = [
		options.binary_borg,
		'check',
	]
	if options.borg_lock_wait is not None:
		cmd.extend([
			'--lock-wait',
			options.borg_lock_wait
		])
	cmd.extend([
		'--last',
		options.borg_check_last,
		options.borg_repository
	])
	proc = subprocess.Popen(cmd, env=borgEnv)
	proc.wait()
	if proc.returncode != 0:
		eprint("borg check failed")
		exit(1)


os.rmdir(tmpDir)

print("BACKUP SUCCESSFUL")
exit(0)

#if Config.get('Storage', 'Method') == 'sshfs':
#	MountSSHFS()
#	UnmountSSHFS()
#else:
#	eprint("Unknown storage method")
#	exit(1)

