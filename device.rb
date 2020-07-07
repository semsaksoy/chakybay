class Device
  @vdom=nil

  def initialize(ssh, vdom)
    @ssh=ssh
    @vdom="config vdom\n edit #{vdom}\n" unless vdom.nil?
  end

  def rules
    t=[]
    p_info= @ssh.exec!("#{@vdom}show firewall policy")
    policy_list=p_info.scan(/edit.*?next/m).flatten
    policy_list.each_with_index do |p, i|
      p_info=p
      name=grep(p_info, /edit\s(.*?)$/)
      s_info= @ssh.exec!("#{@vdom}diagnose firewall iprope show 100004 #{name}")
      rule=name
      sintf=grep(p_info, /set\ssrcintf\s(.*?)$/)
      dintf=grep(p_info, /set\sdstintf\s(.*?)$/)
      saddr=grep(p_info, /set\ssrcaddr\s(.*?)$/)
      daddr=grep(p_info, /set\sdstaddr\s(.*?)$/)
      users=grep(p_info, /set\susers\s(.*?)$/)
      groups=grep(p_info, /set\sgroups\s(.*?)$/)
      service=grep(p_info, /set\sservice\s(.*?)$/)
      nat=grep(p_info, /set\snat\s(.*?)$/)
      ips_profile=grep(p_info, /set\sips-sensor\s(.*?)$/)
      ssl_profile=grep(p_info, /set\sssl-ssh-profile\s(.*?)$/)
      action=grep(p_info, /set\saction\s(.*?)\"?$/)||"deny"
      comments=grep(p_info, /set\scomments\s(.*?)$/)
      status=grep(p_info, /set\sstatus\s(.*?)$/)||"enable"
      pkt=grep(s_info, /pkts\/bytes\=(.*?)\s/)
      cnt=grep(s_info, /hit\scount\:(.*?)\s/)||0
      t<<{order: i+1, rule: rule, action: action, sintf: sintf, dintf: dintf, saddr: saddr, daddr: daddr,
          users:users,groups: groups, service: service, nat: nat,ips_profile:ips_profile,ssl_profile:ssl_profile, comments: comments, status: status, pkt: pkt, cnt: cnt, }
    end
    rules= t
  end

  def nats
    t=[]
    p_info= @ssh.exec!("#{@vdom}show firewall vip")
    policy_list=p_info.scan(/edit.*?next/m).flatten
    policy_list.each_with_index do |p, i|
      name=grep(p, /edit\s(.*?)$/)
      extip=grep(p, /set\sextip\s(.*)/)
      mappedip=grep(p, /set\smappedip\s\"(.*)\"/)
      extport=grep(p, /set\sextport\s(.*)/)
      mappedport=grep(p, /set\smappedport\s(.*)/)
      t<<{order: i+1, name: name, extip: extip, mappedip: mappedip, extport: extport, mappedport: mappedport}
    end
    nats=t
  end

  def user_groups
    t=[]
    u_info= @ssh.exec!("#{@vdom}show user group")
    user_group_list=u_info.scan(/edit.*?next/m).flatten
    user_group_list.each_with_index do |p, i|
      name=grep(p, /edit\s(.*?)$/)
      member=grep(p, /set\smember\s(.*)/)
      group=grep(p, /set\sgroup-name\s(.*)/)
      t<<{order: i+1, name: name, member: member, group: group}
    end
    user_groups=t
  end

  def users
    t=[]
    u_info= @ssh.exec!("#{@vdom}show user local")
    user_list=u_info.scan(/edit.*?next/m).flatten
    user_list.each_with_index do |p, i|
      name=grep(p, /edit\s(.*?)$/)
      type=grep(p, /set\stype\s(.*)/)
      type="local" if type=="password"
      status=grep(p, /set\sstatus\s(.*?)$/)||"enable"
      t<<{order: i+1, name: name, type: type, status: status}
    end
    users=t
  end

  def addressgroup
    t=[]
    u_group= @ssh.exec!("#{@vdom}show firewall addrgrp")
    group_list=u_group.scan(/edit.*?next/m).flatten
    group_list.each_with_index do |p, i|
      name=grep(p, /edit\s(.*?)$/)
      member=grep(p, /set\smember\s(.*)/)

      t<<{order: i+1, name: name, member: member}
    end
    addressgroup=t
  end

  def servicegroup
    t=[]
    u_service= @ssh.exec!("#{@vdom}show firewall service group")
    service_list=u_service.scan(/edit.*?next/m).flatten
    service_list.each_with_index do |p, i|
      name=grep(p, /edit\s(.*?)$/)
      member=grep(p, /set\smember\s(.*)/)
      t<<{order: i+1, name: name, member: member}
    end
    servicegroup=t
  end

end
