import subprocess
import os
from subprocess import Popen, PIPE

#create dev/null object, which will be used with subprocess to avoid broken pipe spam
FNULL = open(os.devnull, 'w')

#Convenience class containing utility methods for executing commands and converting data
class resource(object):
	def __init__(self):
		pass

	def calculate(self, command):
		args = subprocess.Popen([command], shell=True, stderr=FNULL, stdout=PIPE).communicate()[0].strip()
		if args == "0":
			args = 1
		if args == "":
			args = 1		
		return args


	def calculate_gig(self, number):
		modified_number = number / 1000000
		return modified_number


	def calculate_kilo(self, number):
		modified_number = number / 1000 	
		return modified_number

#Class used for cpu stats
class cpu(object):
	def __init__(self):
		pass 

	def load_threshold(self, load, cores):
		procs_over = load - cores
		if procs_over <= 0:
			procs_over = 1
		return procs_over

	def check_usage(self, idle, sys, user, io):
		usage = 100 - idle
		
		usage = str(usage)
		user = str(user)
		sys = str(sys)
		io = str(io)
			
		print("According to iostat data on average the CPU is at " + usage + "% utilization.")
		print("According to iostat data on average " + user + "% of the CPU usage is user.")
		print("According to iostat data on average " + sys + "% of the CPU usage is sys.")
		print ("According to iostat data on average " + io + "% of the CPU usage is IO.\n")


	def check_user_cpu(self, user):
                user = str(user)
                print("The user that has consumed the most cpu based on the process accounting of previously executed commands is " + user + ". Here is a snapshot of this user's processes: \n")
                user_procs = subprocess.call(['ps', '-U', user, '-u', user, 'u'])

				
#Class used for memory stats
class memory(object):
        def __init__(self):
		pass
		
	def pid_usage(self, pid):
		pid = str(pid)
		cmd1 = Popen(["pmap -d " + pid], shell=True, stdout=PIPE)
		cmd2 = Popen(["tail -1"], shell=True, stdin=cmd1.stdout, stdout=PIPE)
		cmd3 = Popen([" awk '{print $4}'"], shell=True, stdin=cmd2.stdout, stdout=PIPE)

		usage = cmd3.communicate()[0].strip()
		return usage

#Class used for iowait stat calculations
class io_wait(object):
	def __init__(self):
		pass

	def top_io_user_average(self, user1, user2, user3, user4, user5):
		
		user1 = str(user1)
		user2 = str(user2)
		user3 = str(user3)
		user4 = str(user4)
		user5 = str(user5)		
		
		print("The system has run iotop in batch mode 5 times. The following users were using the most IO during each iteration: \n")

		user_average = [user1, user2, user3, user4, user5]
		for user in user_average:
			print(user)
		
		print("\n")
		pass

#If I have a network specific function to run, I'll define this later
#class network(object):
#        def __init__(self):
#               pass



#Create dictionary containing commands that will be executed on the system
commands = {"cpu_avg_idle" : "iostat -c | head -4 | awk '{print $6}' | tail -1", 
"cpu_avg_io" : "iostat -c | head -4 | awk '{print $4}' | tail -1",
"cpu_avg_user" : "iostat -c | head -4 | awk '{print $1}' | tail -1",
"cpu_avg_sys" : "iostat -c | head -4 | awk '{print $3}' | tail -1",
"cpu_cores" : "cat /proc/cpuinfo | grep processor | tail -1 | cut -d\: -f2",
"one_load" : "uptime | cut -d\: -f5 | awk '{print $1}' | cut -d\, -f1",
"five_load" : "uptime | cut -d\: -f5 | awk '{print $2}' | cut -d\, -f1",
"fifteen_load" : "uptime | cut -d\: -f5 | awk '{print $3}' | cut -d\, -f1",
"top_cpu_user" : "sa -m| egrep -v '(root|nobody|gdredis)' | head -2 | awk '{print $1}' | tail -1",
"top_cpu_procs" : "ps aux | head -1;ps aux | sort -nrk3 | head -10 | egrep -v USER",
"sorted_procs" : "ps -eo user | sort | uniq -c| sort -nr | head",
"sorted_lastcomm" : "lastcomm |head -10000|egrep -v 'root|nobody'|cut -c 1-10,25-32 |sort|uniq -c|sort -n|tail -10",
"top_mem_pid" : "ps aux | sort -nrk4 | head -1 | awk '{print $2}'",
"top_mem_procs" : "ps aux | head -1; ps aux | sort -nrk4 | head -10",
"total_mem" : "grep -i memtotal /proc/meminfo | awk '{print $2}'",
"free_mem" : "grep -i memfree /proc/meminfo | awk '{print $2}'",
"total_swap" : "grep -i swaptotal /proc/meminfo | awk '{print $2}'",
"swap_free" : "grep -i swapfree /proc/meminfo | awk '{print $2}'",
"top_mem_user" : "sa -mk | egrep -v '(root|nobody|gdredis)' | head -2 | tail -1 | awk '{print $1}'",
"top_io_user" : "iotop -n 1 -b | egrep -v 'Total|TID|root|nobody' | sort -nrk 10 | awk '{print $3}' | head -1",
"nfs_tps" : "iostat -dn| grep content | head -1 | awk '{print $2}'",
"nfs_blk_rps" : "iostat -dn| grep content | head -1 | awk '{print $3}'",
"nfs_blk_wps" : "iostat -dn| grep content | head -1 | awk '{print $4}'",
"network_sar" : "sar -n DEV |head -3; sar -n DEV | grep eth0 | tail -10",
"tcpdump_top_domains" : "tcpdump -i any -nn port 80 or port 443 -A -s0 -c5000 2>/dev/null | egrep 'Host: ' | sort | uniq -cd | sort -rn | head -20",
"tcpdump_top_source_ips" : "tcpdump -i any -nn -A -s0 -c5000 2> /dev/null| grep ' IP ' |awk '{print $3}' | sort | uniq -c |sort -rn | head -20",
"tcpdump_top_dest_ips" : "tcpdump -i any -nn -A -s0 -c5000 2> /dev/null| grep ' IP ' |awk '{print $3}' | sort | uniq -c |sort -rn | head -20",
"netstat_tcp" : "netstat -ant|wc -l",
"netstat_udp" : "netstat -anu|wc -l",
"netstat_sorted_ips" : "netstat -tn|awk '{print $5}'|cut -d: -f1|sort -n|uniq -dc|sort -rn | head -20",
"netstat_con_types" : "netstat -ant|awk '{print $NF}'|sort|uniq -c|sort -nr| head",
"packets_received" : "ifconfig | grep -A6 bond0 | grep 'RX packets' | awk '{print $2}' | cut -d: -f2",
"packets_transfered" : "ifconfig | grep -A6 bond0 | grep 'TX packets' | awk '{print $2}' | cut -d: -f2",
"bytes_received" : "ifconfig | grep -A6 bond0 | grep 'RX bytes' | awk '{print $3, $4}' | sed 's/[)(]//g'",
"bytes_transfered" : "ifconfig | grep -A6 bond0 | grep 'TX bytes' | awk '{print $7, $8}' | sed 's/[)(]//g'",
}

#Test dictionary values
#for x in commands:
#	print commands[x]

#Test varitables
"""
cpu_avg_idle = float(8.0)
cpu_avg_io = float(10.7)
cpu_avg_user = float(60.5)
cpu_avg_sys = float(30.3)
cpu_cores = int(4)
one_load = float(35)
five_load = float(20)
fifteen_load = float(10)
swap_used = 32
"""


#Set CPU variables
cpu_avg_idle = float(resource().calculate(commands['cpu_avg_idle']))
cpu_avg_io = float(resource().calculate(commands['cpu_avg_io']))
cpu_avg_user = float(resource().calculate(commands['cpu_avg_user']))
cpu_avg_sys = float(resource().calculate(commands['cpu_avg_sys']))
cpu_cores = int(resource().calculate(commands['cpu_cores']))
#Have to account for processor 0
cpu_cores = cpu_cores + 1
one_load = float(resource().calculate(commands['one_load']))
five_load = float(resource().calculate(commands['five_load']))
fifteen_load = float(resource().calculate(commands['fifteen_load']))
load_average = float(one_load + five_load + fifteen_load) / 3
procs_over = int(cpu().load_threshold(load_average, cpu_cores))
top_cpu_user = resource().calculate(commands['top_cpu_user'])

#Set Memory variables
top_mem_pid = str(resource().calculate(commands['top_mem_pid']))
pid_mem_usage = str(memory().pid_usage(top_mem_pid))
top_mem_user = str(resource().calculate(commands['top_mem_user']))
total_mem = int(resource().calculate(commands['total_mem']))
total_mem_gig = int(resource().calculate_gig(total_mem))
free_mem = int(resource().calculate(commands['free_mem'])) #kilobytes
free_mem_gig = int(resource().calculate_gig(free_mem))
total_swap = int(resource().calculate(commands['total_swap']))
swap_free = int(resource().calculate(commands['swap_free']))
swap_used = total_swap - swap_free

#Set IO variables
io_user1 = str(resource().calculate(commands['top_io_user']))
io_user2 = str(resource().calculate(commands['top_io_user']))
io_user3 = str(resource().calculate(commands['top_io_user']))
io_user4 = str(resource().calculate(commands['top_io_user']))
io_user5 = str(resource().calculate(commands['top_io_user']))

#Set network variables:
#tcpdump variables will need to be evaluated only if needed, due to the amount of timee they take
#tcpdump_top_domains = str(resource().calculate(commands['tcpdump_top_domains']))
#tcpdump_top_source_ips = str(resource().calculate(commands['tcpdump_top_source_ips']))
#tcpdump_top_dest_ips = str(resource().calculate(commands['tcpdump_top_dest_ips']))
network_sar = str(resource().calculate(commands['network_sar']))
netstat_sorted_ips = str(resource().calculate(commands['netstat_sorted_ips']))
netstat_tcp = int(resource().calculate(commands['netstat_tcp']))
netstat_udp = int(resource().calculate(commands['netstat_udp']))
netstat_total = netstat_tcp + netstat_udp
netstat_con_types = str(resource().calculate(commands['netstat_con_types']))
packets_received = str(resource().calculate(commands['packets_received']))
packets_transfered = str(resource().calculate(commands['packets_transfered']))
bytes_received = str(resource().calculate(commands['bytes_received']))
bytes_transfered = str(resource().calculate(commands['bytes_transfered']))

#Set NFS variables
nfs_tps = float(resource().calculate(commands['nfs_tps']))
nfs_blk_rps = float(resource().calculate(commands['nfs_blk_rps']))
nfs_blk_wps = float(resource().calculate(commands['nfs_blk_wps']))

#Testing class methods~
#print cpu().check_usage(cpu_avg_idle,cpu_avg_sys,cpu_avg_user,cpu_avg_io)
#cpu().check_user_cpu(top_cpu_user)
#io_wait().top_io_user_average(io_user1, io_user2, io_user3, io_user4, io_user5)



#Server analyzing logic
#Issue counter, increment if any issue conditions are found
issue_check = 0

#Start with displaying system load, check if it is over recommended threshold
print("Checking sytem load...")
print("The aggregate system load is " + str(load_average) + "\n")
if procs_over > 1: 
	print("There are " + str(cpu_cores) + " CPU cores on this system. There should only be 1 load per core, so over the course of 15 minutes the system load is " + str(procs_over) + " over where it should be. The current 1 minute load is " + str(one_load) + ".\n") 
	issue_check = issue_check + 1

#CPU checks 
if cpu_avg_idle < 50:
	print("Accoring to iostat data the CPU is less than 50% idle. Checking CPU usage...\n")
	cpu().check_usage(cpu_avg_idle,cpu_avg_sys,cpu_avg_user,cpu_avg_io)
	issue_check = issue_check + 1
	
	if cpu_avg_io > 5:
		print("Accoring to iostat data the system IO average is above 5% this could be causing perfomance issues.\n")
		io_wait().top_io_user_average(io_user1, io_user2, io_user3, io_user4, io_user5)
		print("\n")

	if cpu_avg_user > cpu_avg_sys:
		print("The CPU user usage is higher than the CPU system usage.\n")
		cpu().check_user_cpu(top_cpu_user)
		print("\nThat does not mean that this user is necessarily the problem. Here are the top 10 CPU consuming processes in the current process table:\n")
		print(resource().calculate(commands['top_cpu_procs']))	
		print("\n")

	if cpu_avg_sys >  cpu_avg_user:
		print("The CPU system usage is higher than the CPU user usage.\n")
		print("\nHere are the top 10 CPU consuming processes:")
		print(resource().calculate(commands['top_cpu_procs']))
		print("\n")

 		

#Memory checks:
if swap_used > 1:
	issue_check = issue_check + 1
	print("There is swap in use, checking system memory...")
	print("There is " + str(total_mem_gig) + "G of memory on the system.")
	print("There is " + str(free_mem) + "kB of free memory available.")
	print("There is " + str(swap_used) + "kB of swap in use.")
	print("The user using the most memory according the process accounting data is " + str(top_mem_user) + ".")
	print("The pid consuming the most memory is " + str(top_mem_pid) + ". This pid's writable/private usage is " + str(pid_mem_usage) + " according to pmap data.")
	print("\n")
	print("Here is a sorted list of the top 10 memory consuming procs:")
	print(resource().calculate(commands['top_mem_procs']))
	print("\n")

#Network check
if netstat_total > 1500:
	issue_check = issue_check + 1
	print("There are over 1.5k connections in netstat, running network checks...")
	print("There are " +  str(netstat_tcp) + " tcp connections in netstat")
	print("There are " +  str(netstat_udp) + " udp connections in netstat")
	print("Here is alist of the sorted connection types in netstat: \n" )
	print(netstat_con_types)
	print("Here is a sorted list of the IPs with the most connections to the server in netstat: \n")
	print(netstat_sorted_ips)
	print("\n")
	print("Calculating ifconfig stats...")
	print("There are " + str(bytes_received) + " bytes received on the NIC")
	print("There are " + str(bytes_transfered) + " bytes transfered on the NIC")
	print("There are " + str(packets_received) + " packets received on the NIC")
	print("There are " + str(packets_transfered) + " packets transfered on the NIC")
	print("\n")
	print("Here is the tail end of  the sar network stats: \n")
	print(network_sar)
	print("\n")
	print("Parsing data from 3 tcpdumps, 5k packets a piece. this might take a few...")
	print("Here are the top request domains in the first packet capture: \n")
	print(resource().calculate(commands['tcpdump_top_domains']))
	print("\n")
	print("Here are the top source IPs in the second packet capture: \n")
	print(resource().calculate(commands['tcpdump_top_source_ips']))
	print("\n")
	print("Here are the top destination IPs in the third packet capture: \n")
	print(resource().calculate(commands['tcpdump_top_dest_ips']))

#General process info -need to figure out the conditions for when this should be displayed
"""
print "\n"
print "Here is a sorted list of the process table:\n"
print resource().calculate(commands['sorted_procs'])
print "\n"

print "Here is a sorted list of the last processed commands:\n"
print resource().calculate(commands['sorted_lastcomm'])
print "\n"
"""

#Testing variable output~
"""
print "top_mem_user: " + str(top_mem_user)
print "top_mem_pid: " + str(top_mem_pid)
print "pid_mem_usage: " + str(pid_mem_usage)
print "total_mem: " + str(total_mem)
print "free_mem: " + str(free_mem)
print "total_swap: " + str(total_swap)
print "swap_free: " + str(swap_free)
print "total_mem_gig: " + str(total_mem_gig)
print "swap_used: " + str(swap_used)

print "cpu_avg_idle: " + str(cpu_avg_idle)
print "cpu_avg_io: " + str(cpu_avg_io)
print "cpu_avg_user: " + str(cpu_avg_user)
print "cpu_avg_sys: " + str(cpu_avg_sys)
print "cpu_avg_sys: " + str(cpu_cores)
print "one_load: " + str(one_load)
print "five_load: " + str(five_load)
print "fifteen_load: " + str(fifteen_load)
print "load_average: " + str(load_average)
print "procs_over: " + str(procs_over)

print "io_user1: " + str(io_user1)
print "io_user2: " + str(io_user2)
print "io_user3: " + str(io_user3)
print "io_user4: " + str(io_user4)
print "io_user4: " + str(io_user4)

print "tcpdump_top_domains" + str(tcpdump_top_domains) 
print "tcpdump_top_source_ips:\n" + str(tcpdump_top_source_ips)
print "tcpdump_top_dest_ips:\n" + str(tcpdump_top_dest_ips)
print "netstat_sorted_ips:\n" + str(netstat_sorted_ips)
print "netstat_tcp: " + str(netstat_tcp)
print "netstat_udp: " + str(netstat_udp)
print "netstat_con_types:\n" + str(netstat_con_types)
print "packets_received: " + str(packets_received)
print "packets_transfered: " + str(packets_transfered)
print "bytes_received: " + str(bytes_received)
print "bytes_transfered: " + str(bytes_transfered)
print "network_sar: " + str(network_sar)

print "nfs_tps: " + str(nfs_tps)
print "nfs_blk_rps: " + str(nfs_blk_rps)
print "nfs_blk_wps: " + str(nfs_blk_wps)
"""
#Need to close the dev/null object that was opened earlier
FNULL.close()
