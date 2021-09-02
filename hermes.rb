#!/usr/bin/ruby -w
#

require 'fileutils'
require 'colored'
require 'io/console'
require 'optparse'

nmap = 'nmap'
nessus = 'nessus'
time1 = Time.new
year = time1.strftime("%Y")
clear = "clear"
system(clear)

puts '***************************************************************************'
puts '*          Pentest Project Wrapper Script                                 *'
puts '*          This script is meant to run from /opt/newhermes on Kali        *'
puts '*                                                                         *'
puts '*                                                                         *'
puts '*  1. Creates project directory                                           *'
puts '*  2. Takes scope input and creats scopelist                              *'
puts '*  3. Runs Nmap against host list using PCI switches                      *'
puts '*  4. Runs Nessus against Nmap results                                    *'
puts '*  5. Runs EyeWitness and Yasuo against Nmap results                            *'
puts '*  6. Creates Metasploit resource scripts that:                           *'
puts '*     A: Creates project and workspace                                    *'
puts '*     B: Imports Nessus Results                                           *'
puts '*     C: Runs Service Scans resource script                               *'
puts '*     D: Outputs host and service csv files to project directory          *'
puts '*                                                                         *'
puts '***************************************************************************'

options = {}
optparse = OptionParser.new do |opts|
  opts.banner += "Usage: ruby hermes.rb [options]"
  options[:password] = nil
  options[:username] = nil
  options[:accesskey] = nil
  options[:secretkey] = nil
  options[:scopefile] = nil
  options[:mainframe] = false
  options[:mailfrom] = nil
  options[:nmapxml] = nil
  options[:mailto] = nil
  options[:dryrun] = false
  options[:skipnmap] = false
  opts.on( '-n', '--name PROJECT', 'Project name' ) do |name|
    options[:name] = name
  end
  opts.on( '-p', '--password PASS', 'Password to Nessus account' ) do |pass|
    options[:password] = pass
  end
  opts.on( '-u', '--username USER', 'Username of Nessus account' ) do |user|
    options[:username] = user
  end
  opts.on( '-a', '--accesskey ACCESSKEY', 'Accesskey to Nessus account' ) do |accesskey|
    options[:accesskey] = accesskey
  end
  opts.on( '-k', '--secretkey SECRETKEY', 'Secretkey of Nessus account' ) do |secretkey|
    options[:secretkey] = secretkey
  end
  opts.on( '-f', '--file FILE', 'Filename for scope list' ) do |file|
    options[:scopefile] = file
  end
  opts.on( '-s', '--sender user@host.com', 'Mail sender address' ) do |mailfrom|
    options[:mailfrom] = mailfrom
  end
  opts.on( '-t', '--to user@host.com', 'Mail to address' ) do |mailto|
    options[:mailto] = mailto
  end
  opts.on( '-e', '--stophour HOUR', 'Hour to pause' ) do |stophour|
    options[:stophour] = stophour
  end
  opts.on( '-b', '--starthour HOUR', 'Hour to resume' ) do |starthour|
    options[:starthour] = starthour
  end
  opts.on( '-m', '--mainframe', 'Use mainframe nmap command' ) do |mainframe|
    options[:mainframe] = true
  end
  opts.on( '-x', '--skipnmap', 'skip running the nmap command' ) do |skipnmap|
    options[:skipnmap] = true
  end
  opts.on( '--nmapxml FILE', 'Specify alternate nmap xml file (ignored if not using skipnmap)' ) do |nmapxml|
    options[:nmapxml] = nmapxml
  end
  opts.on( '-d', '--dryrun', 'Skip all commands' ) do |dryrun|
    options[:dryrun] = true
  end
  opts.on_tail( '-h', '--help', 'Display this screen' ) do
    puts opts
    exit
  end

  opts.parse!
end



yasuo = '/opt/newhermes/yasuo/yasuo.rb'
if File.exist?(yasuo)
        puts '[+] Yasuo Found. Continuing....'.green
else
        puts '[-] Yasuo dependency not found. Place Yasuo in /opt'.red
        puts '    https://github.com/0xsauby/yasuo.git'.red
        puts ' gem install ruby-nmap net-http-persistent mechanize colorize text-table'.red
exit
end

nessusparser = '/opt/newhermes/nessus_http_api.usb.pl'
if File.exist?(nessusparser)
        puts '[+] Nessus_parser Found. Continuing....'.green
else
        puts '[-] Nessus_parser dependency not found. Requires /opt/newhermes/nessus_parser.pl'.red
exit
end


eyewitness= '/opt/newhermes/EyeWitness/EyeWitness.py'
if File.exist?(eyewitness) then
   puts '[+] EyeWitness Found. Continuing....'.green
else
  puts '[-] EyeWitness dependency not found. Place rawr in /opt'.red
  puts '    Clone rawr to /opt. git clone https://bitbucket.org/al14s/rawr.git'.red
exit
end


msfrc= '/opt/msf_resources/services_scanv2.rc'
if File.exist?(msfrc) then
	puts '[+] MSF Service Scan Resource Found. Continuing...'.green
    else
        puts '[-] MSF Services Scan Resource file was not found in '.green + msfrc.green
        exit
end



# End dependency checks

if !options[:name]
  puts "Please enter your project name: ".yellow
  project = gets.chomp
else
  project = options[:name]
end

sudo_user = ENV['SUDO_USER']
home = File.expand_path('~')
if !(sudo_user.empty?)
  homecmd = "getent passwd " + sudo_user + " | cut -d : -f 6"
  home = `#{homecmd}`.chomp
end

#puts home
timestamp = Time.now.strftime("%Y%m%d-%H%M")
scope = "scope" + timestamp + ".txt"
projectdir = home + '/pentests/' + year + "/" + project
nmapdir = projectdir + '/' + nmap
projlog = projectdir + '/' + project + ".log"
nessusdir = projectdir + '/' + nessus
nessusfile = nessusdir + "/" + project + "-" + timestamp + ".nessus"
reportdir = projectdir + '/Yasuo_reports/'
images = projectdir + '/EyeWitness_screenshots/'
yasuoout = reportdir + "yasuo_" + timestamp + ".txt"
user = ENV['USER']




if File.exist?(projectdir) then
   	puts '[+] Project Directory Existed. Continuing...'.green
  else
        FileUtils::mkdir_p(projectdir)
   	puts '[+] Created Project Directory in Home Dir.'.green
end



#create project log
if File.exist?(projlog) then
  	puts '[+] Project must have been ran before, log already exists, appending...'.green + projectdir.green
  	plog = File.open(projlog, "a")
  	plog.puts "/n"
  	plog.puts "*****************************************************"
  	plog.puts "Script started at: " + time1.inspect
  	plog.puts "Files are being stored:"
        plog.puts "Project Directory: " + projectdir
        plog.puts "Script Log: " + projlog
        plog.puts "Nmap Directory: " + nmapdir
        plog.puts "Nessus File: " + nessusfile
	plog.puts "Screenshots: " + images
        plog.puts "Reports Diretory: " + reportdir
        plog.puts "Yasuo Report: " + yasuoout
	plog.close
  else
  	plog =  File.open(projlog, "w")
  	plog.puts "*****************************************************"
  	plog.puts "Script started at: " + time1.inspect
  	plog.puts "Files are being stored:"
	plog.puts "Project Directory: " + projectdir
    	plog.puts "Script Log: " + projlog
        plog.puts "Nmap Results: " + nmapdir
	plog.puts "Nessus File: " + nessusfile
	plog.puts "Screen Shots: " + images
        plog.puts "Reports Directory: " + reportdir
        plog.puts "Yasuo Report: " + yasuoout
	plog.close
end



#test for existing directories and create if they don't exist
if File.exist?(nmapdir) then
   	puts '[+] Nmap Directory already exists, storing nmap results '.green + nmapdir.green
   	plog = File.open(projlog, "a")
   	plog.puts "Nmap directory already exists. Overwriting!"
   	plog.close
   else
   	puts '[+] Creating nmap Directory to store nmap results in'.green
   	Dir.mkdir(nmapdir)
   	plog = File.open(projlog, "a")
   	plog.puts "Created nmap directory in project directory."
   	plog.close
end

if File.exist?(nessusdir) then
        puts '[+] Nessus directory alrady exists, storing Nessus results here: '.green + nessusdir.green
        plog = File.open(projlog, "a")
        plog.puts "Nessus directory already existed. Putting new results in there"
        plog.close
else
        Dir.mkdir(nessusdir)
        puts "[+] Creating Nessus directory to store nessus files. Located: ".green + nessusdir.green
        plog = File.open(projlog, "a")
        plog.puts "Created Nessus Directory: " + nessusdir
        plog.close
end

if File.exist?(reportdir) then
        puts '[+] Report Directory Existed. Continuing...'.green
        plog = File.open(projlog, "a")
        plog.puts "Report directory already exists, storing reports in: " + reportdir
        plog.close
else
        FileUtils::mkdir_p(reportdir)
        puts '[+] Created Report Directory....'.green
end

if File.exist?(images) then
        puts '[+] Images Directory Existed. Continuing...'.green
        plog = File.open(projlog, "a")
        plog.puts "Images directory already exists, storing reports in: " + reportdir
        plog.close
else
        FileUtils::mkdir_p(images)
        puts '[+] Created Images Directory....'.green
end

#write project info  in users home directory for sudo script to read and put .nessus file.
tmpfile = home + "/nessus.txt"

#puts tmpfile
if File.exist?(tmpfile)
  File.delete(tmpfile)
  sudoloc =  File.open(tmpfile, "w")
  sudoloc.puts projectdir
  sudoloc.puts project
  sudoloc.close
else
  sudoloc = File.open(tmpfile, "w")
  sudoloc.puts projectdir
  sudoloc.puts project
  sudoloc.close
end



if !options[:scopefile]
  puts "Paste in scope list for project. Finish input with Ctrl + D".yellow
  $/ = "\0"
  targetList = STDIN.gets
  #exit if targetList.empty?
  $/ = "\n"
else
  if File.exist?(options[:scopefile])
    targetList = File.read(options[:scopefile])
  else
    puts "File options[:file] does not exist"
    exit
  end
end

scopefile = projectdir + '/' + project + '_' + scope


# NOTE:  Make it move existing scope into fullscopelist and append if one exists.                                                 
if File.exist?(scopefile)
   	puts '[-] Script found existing scope list. Deleting and creating new scopelist....'.red
   	File.delete(scopefile)
   	fscope = File.open(scopefile, "w")
   	fscope.puts(targetList)
   	fscope.close
   	plog = File.open(projlog, "a")
   	plog.puts "Scope list alrady existed! Deleted old scope list and created new one."
   	plog.close
        system("dos2unix #{scopefile}")
    else
   	fscope = File.open(scopefile, "w")
   	fscope.puts(targetList)
   	fscope.close
   	plog = File.open(projlog, "a")
   	plog.puts "Using Scope of: "
   	plog.puts(targetList)
        plog.close
        system("dos2unix #{scopefile}")
end

#gets username and password for Nessus

if !options[:accesskey]
  puts "Please Enter your Nessus Access Key [".yellow + sudo_user + "]" .yellow
  nuser = STDIN.gets.chomp
  if nuser.empty?
    nuser = sudo_user
  end
else
  accesskey = options[:accesskey]
end
exit if accesskey.empty?

if !options[:secretkey]
  puts "Please Enter your Nessus Secret Key".yellow
  secretkey = STDIN.noecho(&:gets).chomp
else
  secretkey = options[:secretkey]
end
exit if secretkey.empty?


# Run nessus and nmap script
puts "[+] Testing nessus credentials".green
nessusserver = '127.0.0.1'
nessusserver = 'https://127.0.0.1:8834'


if (options[:skipnmap] && options[:nmapxml] )
  if !options[:nmapxml] =~ /.xml$/
    puts "Error nmapxml must end with .xml suffix".red
    exit
  end
  nmapoutfile = options[:nmapxml]
  nmapout = options[:nmapxml].chomp('.xml')
else
  nmapoutfile = projectdir + '/nmap/' + project + "-" + timestamp  + ".log.xml"
  nmapout     = projectdir + '/nmap/' + project + "-" + timestamp + ".log"
end

            

scriptcmd = "-n " + nessusserver + " " + "-a " + accesskey + " " + "-k " + secretkey + " --targetsfile=" + scopefile + " --nmapfile=" + nmapout + " --outputfile=" + nessusfile + " -c " + project
if options[:mainframe]
  scriptcmd = scriptcmd + " -m"
end
if options[:mailfrom]
  scriptcmd = scriptcmd + " -s " + options[:mailfrom]
end
if options[:mailto]
  scriptcmd = scriptcmd + " -t " + options[:mailto]
end
if options[:skipnmap]
  scriptcmd = scriptcmd + " --skipnmap "
end
if options[:stophour]
  scriptcmd = scriptcmd + " --stophour " + options[:stophour]
end
if options[:starthour]
  scriptcmd = scriptcmd + " --starthour " + options[:starthour]
end

puts "command being passed to nmap_httpscript:= " + scriptcmd
fullscriptcmd = "perl /opt/newhermes/nessus_http_api.usb.pl " + scriptcmd
#puts "full command = " + fullscriptcmd
plog = File.open(projlog, "a")
        plog.puts "Running Nmap and Nessus"
        plog.close
        

if !options[:dryrun]
  system(fullscriptcmd)
else
  puts fullscriptcmd.magenta
end

if ! options[:mainframe]
  # Run EyeWtiness and ouput to project folder
  puts "[+] Running EyeWitness on Nmap Results....".green
  eyewitnesscmd = 'python ' + "/opt/newhermes/EyeWitness/EyeWitness.py" + " -x " + nmapoutfile + " -d " + images + " " + "--all-protocols" + " " + "--no-pro\
mpt"
  #puts rawrcmd
  puts eyewitnesscmd.magenta
  if !options[:dryrun]
    system(eyewitnesscmd)
  end
end

#Run Yasuo
puts "[+] Running Yasuo on Nmap Results....".green
yasuoout = reportdir + "yasuo_" + timestamp + ".txt"
puts yasuoout
yasuocmd = 'ruby ' + yasuo + ' -s /opt/newhermes/yasuo/signatures.yaml -f ' + nmapoutfile + " > " + yasuoout
puts yasuocmd.magenta
if !options[:dryrun]
  system(yasuocmd)
end


#Set ownership of screenshots directory recursively to user
chcmd = 'sudo chown -R ' + sudo_user + " " + images
system(chcmd)


#Build metasploit resource file and combine nmap and nessus reports.
puts "[+] Building Metasploit Resource File....".green

msfproject = "project -c " + project + "_" + year
dbimport = "db_import " + nmapoutfile
nsimport = "db_import " + nessusfile
servscan = "resource " + "/opt/msf_resources/services_scanv2.rc"
hostout = "hosts -c address,os_name,os_flavor,os_sp,vuln_count,service_count,state -o " + projectdir + '/' + "hosts_" + project + ".csv"
servicesout = "services -o " + projectdir + '/' + "services_" + project + ".csv"
msfresource = projectdir + '/' + project + '_msfresource' + timestamp + '.rc'

plog = File.open(projlog, "a")
        plog.puts "Building MSF resource file... "
        plog.close


if File.exist?(msfresource)
   puts '[-] Metasploit resource file already exists. Creatin backup and then creating new resource file'.red
   bkup = projectdir + '/' + project + '_msfresource.bkup'
   FileUtils.move(msfresource, bkup)
   File.delete(msfresource)
   plog = File.open(projlog, "a")
   plog.puts "MSF resource file already existed. Renamed to .bkup and created new file!"
   plog.close
end

rc = File.open(msfresource, "w")
rc.puts "resource /opt/msf_resources/startup.rc"
rc.puts(msfproject)
#rc.puts(dbimport)
#rc.puts(nsimport)
Dir.glob(nmapdir + "/*.xml" ) do |nmfile|
  rc.puts "db_import "  + nmfile
end
Dir.glob(nessusdir + "/*.nessus" ) do |nmfile|
  rc.puts "db_import "  + nmfile
end
rc.puts(servscan)
rc.puts(hostout)
rc.puts(servicesout)

rc.close

plog = File.open(projlog, "a")
plog.puts "Finished Building MSF resource file "
plog.close

puts '[+] Metasploit Resource File has been created for project...'.green
puts 'Run metasploit and then call resource file with: resource '.green + msfresource.green
#*****************************************************************************************************************

#cleanup tempfile used for sudo to know projectdir
if File.exist?(tmpfile)
   File.delete(tmpfile)
   plog = File.open(projlog, "a")
   plog.puts "Deleted temp file for sudo to know project dir."
   plog.close
else
   plog = File.open(projlog, "a")
   plog.puts "Temp file for sudo did not exist to delete."
  plog.close
end


plog = File.open(projlog, "a")
plog.puts "Script Finished at: " + time1.inspect
plog.puts "******************************"
plog.close

puts "Nmap file (s) used: " + nmapoutfile
puts "Nessus file(s) used: " + nessusfile



exit
