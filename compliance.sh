#-----------------------------------------
# Configurations
#-----------------------------------------
SSH_Params(){
cat <<_CONF
Protocol 2
SyslogFacility AUTHPRIV
LogLevel INFO
LoginGraceTime 2m
PermitRootLogin no
MaxAuthTries 3
PermitEmptyPasswords no
PasswordAuthentication yes
ClientAliveInterval 7m
ClientAliveCountMax 3
MaxStartups 4
Banner /etc/issue.ssh
_CONF
}

SystemServiceList() {
# enable = level 253
cat <<_list
auditd                  enable
rscd                    enable
iptables                enable
sysstat                 enable
rwalld                  disable
pcmcia                  disable
apmd                    disable
avahi-daemon            disable
sendmail                disable
smb                     disable
nfs                     disable
autofs                  disable
nfslock			disable
ypbind                  disable
ypserv                  disable
yppasswdd               disable
portmap                 disable
netfs                   disable
cups                    disable
hpoj			disable
lpd			disable
squid                   disable
kudzu                   disable
bluetooth               disable
cups-config-daemon      disable
_list

}


Audit_Perm() {
# it will set perm 0600 using Audit_control Function
cat <<_Params
/var/log/messages
/var/log/boot.log
/var/log/maillog
/var/log/sudo.log
/var/log/secure
/var/log/cron
/var/log/dmesg
_Params
}

User_Perm(){
# file			mode	uid:gid
cat <<_Params
/etc/passwd		644	0:0
/etc/group		644	0:0	
/etc/shadow		400	0:0
/etc/crontab		400	0:0	
/etc/cron.deny		400	0:0
/etc/at.deny		400	0:0
/etc/cron.allow		400	0:0
/etc/at.allow		400	0:0
/var/spool/cron		700	0:0
/etc/cron.d		700	0:0
/etc/cron.hourly	700	0:0
/etc/cron.monthly	700	0:0
/etc/cron.daily		700	0:0
/etc/cron.weekly	700	0:0
_Params

}

Disable_Users_list(){

cat <<_list
lp
sync
shutdown
halt
mail
news
uucp
operator
games
gopher
ftp
_list

}

# add groups which you want to disable 
Disable_Groups_list=( lp games uucp )

Log_Params() {
cat <<_Params
*.info;mail.none;authpriv.none;cron.none                /var/log/messages
authpriv.*                                              /var/log/secure
mail.*                                                  -/var/log/maillog
_Params
# log for sudo will done manually in Log_Audit Function
}

Kernel_Params() {

cat <<_Params
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
_Params

}

HostsDeny(){

cat <<_EOF
#
# hosts.deny    This file describes the names of the hosts which are
#               *not* allowed to use the local INET services, as decided
#               by the '/usr/sbin/tcpd' server.
#
# The portmap line is redundant, but it is left to remind you that
# the new secure portmap uses hosts.deny and hosts.allow.  In particular
# you should know that NFS uses portmap!

All: ALL
_EOF

}

#-----------------------------------------
# Global Variables
#-----------------------------------------
SSHD_Conf="/etc/ssh/sshd_config"
Hosts_Deny="/etc/hosts.deny"
TST=1

#-----------------------------------------
# Functions
#-----------------------------------------
Checking() {
    msg="${@}"
    char=${#msg}
    col_size=$(( $(tput cols) - 45))
    col=$(( col_size - char))
	printf '%s%*s%s\n' $(tput setaf 3 ; tput bold )"${@}" $col "[   OK    ]"
    tput sgr 0
}

OK() {
	msg="${@}"
	char=${#msg}
	col_size=$(( $(tput cols) - 45))
	col=$(( col_size - char))
	printf '%s%*s%s\n' $(tput bold )"${@}" $col "[ Success ]"
	tput sgr 0
}
Line() {
	col_size=$(( $(tput cols) - 45))
	for (( i=$col_size; i>0; i--))
	do
		printf "%s" "${@}"
	done
}
Warning() {
	msg="${@}"
	char=${#msg}
	col_size=$(( $(tput cols) - 45))
	col=$(( col_size - char))
	printf '%s%*s%s\n' $(tput setaf 1; tput bold )"${@}" $col "[ Warning ]"
	tput sgr 0
}

Exists() {
	msg="${@}"
	char=${#msg}
	col_size=$(( $(tput cols) - 45))
	col=$(( col_size - char))
	printf '%s%*s%s\n' $(tput setaf 2; tput bold )"${@}" $col "[  Exist  ]"
	tput sgr 0
}

Show_menu() {
clear
cat <<_EOF
    ------------------------------------
    |              Menu                |
    ------------------------------------
    |   1. SSH Security Check          |
    |   2. TCP Wrapper                 |
    |   3. FileSystem Security Check   |
    |   4. Kernl Level Security        |
    |   5. Log & Audit Control         |
    |   6. Service Control             |
    ------------------------------------
############################################

_EOF
}

Sub_menu() {
Line "-" 
echo ""
cat <<_EOF
1. Return Main Menu
2. Exit Program
_EOF
Line "="
echo ""
}
ReadOnly() {
	local on_off=$1
	conf=$2
	case $1 in 
		on) 	chmod u-w $conf ;
			chattr +i $conf ;
					;;
		off) 	chattr -i $conf ;
			chmod u+w $conf ;
					;;
	esac

}

ChecknAdd() {
    local input_string=${1}
    local config_file=${2}
    local grep_search_pattern="$(echo "${input_string}" |\
                                sed -ne 's/\(\S*\) \([A-Za-z0-9.]*\)/^[ ^\\t]*\1*[ ^\\t]*\2/p' )"
    local restruck_sting_handle_backslash=$( echo ${input_string} | sed 's/\(\/\)/\\\//g' )
    local sed_pattern_1=$(  echo "${restruck_sting_handle_backslash}" |\
                            sed -ne 's/\(\S*\) \([A-Za-z0-9.\\\/]*\)/\"\s\/\\(^\\s*\1\\s*[.0-9A-Za-z\\\/]*\\\)\/#\\1\\n\1 \2\/\"/p')
    local sed_patter_2=$(   echo "${restruck_sting_handle_backslash}" |\
                            sed -ne 's/\(\S*\) \([A-Za-z0-9.\\\/]*\)/\"1\,\/\1\/\{s\/\\(\^\\s*#\\s*\1\\\s*[,.0-9A-Za-z\\\/]*\\\)\/\\1 \\n\1 \2\/\}" /p' )

    [[ -z $config_file ]] && { Warning "Error: Config file not Specified.."; exit 1; };

    if grep -q -P "${grep_search_pattern}" $config_file ; then
         Exists "${input_string}"
    else
         OK "Option ${input_string} Updating...."
         echo sed -i.bkp-$(date +%F) $sed_pattern_1 $config_file | sh

         if ! grep -q -P "${grep_search_pattern}" $config_file ; then
            echo sed -i.bkp-$(date +%F) ${sed_patter_2} $config_file | sh
	 OK "Done"
         fi
    fi

}



SSH_Security_check() {
	TempConf=$(mktemp)
	SSH_Params > "${TempConf}"
	ReadOnly off $SSHD_Conf
	while read value 
	do
		ChecknAdd "${value}" $SSHD_Conf
	done < "${TempConf}"
	rm -f "${TempConf}"
	ReadOnly on $SSHD_Conf
}


TCPWrapper_check() {

	if ! grep -iqP '^[ ^\t]*all*[ ^\t]*:*[ ^\t]*all' $Hosts_Deny >/dev/null 2>&1; then
		cp ${Hosts_Deny}{,-bkp-$(date +%F)} >/dev/null 2>&1 
		OK "Updateing $Hosts_Deny ...."
		HostsDeny > ${Hosts_Deny}				
	else
		Exists "ALL:ALL in $Hosts_Deny"
	fi 

}

FileSystemChecks() {

	if ! $( mount | grep -q "/tmp" ); then
		Warning "/tmp not exists.."
	else
		OK "Updating /etc/fstab for /tmp partition.."
	fi
	
	if ! $( mount | grep -q "/dev/shm" ); then
                Warning "/dev/shm not exists.."
        else
		if [[ $(mount | grep "/dev/shm" | awk '{print $NF}') = '(rw,noexec,nosuid,nodev)' ]]; then

			Exists "$(mount | grep "/dev/shm" | awk '{print $NF}')"	
		else
                	OK "Updating /etc/fstab for /dev/shm partition.."
			Fstab='/etc/fstab'
			cp ${Fstab}{,-bkp-$(date +%F)} >/dev/null 2>&1	
			awk '1;/\/dev\/shm/{$4="nosuid,nodev,noexec";print}' $Fstab | column -t > $Fstab
			sed -i '/\/dev\/shm/{s/^/#/;:a;n;ba}' $Fstab
			mount -o remount /dev/shm
		fi
        fi



}

Kernel_Tuning() {

	Conf='/etc/sysctl.conf'
	Tmp_params=$(mktemp)
	Kernel_Params > "${Tmp_params}"
	while read  values 
	do
		search_pattern=$( echo "${values}" |\
			 sed -ne 's/\(\S*\) \(=\) \([A-Za-z0-9.]*\)/^[ ^\\t]*\1*[ ^\\t]*\2\*[ ^\\t]*/p' )
		if grep -qP "${search_pattern}" $Conf; then
            
        # the value adding check already exists or not 
        exist_or_not=$( echo "${values}" |\
                        sed -ne 's/\(\S*\) \(=\) \([A-Za-z0-9.]*\)/^[ ^\\t]*\1*[ ^\\t]*\2\*[ ^\\t]*\3/p')

            if grep -qP "${exist_or_not}" $Conf; then
                Exists "$values" 
                continue
            else

			# if exists then comment old and add new
			sed_pattern=$( echo "${values}" |\
		 sed -ne 's/\(\S*\) \([A-Za-z0-9.\\\/=]*\) \([0-9]*\)/ \"\s\/\\(^\\s*\1\\s*[.0-9A-Za-z\\\/=]\\s*[.0-9A-Za-z\/]*\\\)\/# \\1\\n\1 \2 \3\/\"/p'	)
			echo sed -i ${sed_pattern} $Conf | sh
		    OK "${values}"
            fi
		else
			echo "${values}" >> $Conf
		    OK "${values}"	
		fi

	done < "${Tmp_params}"
	rm -f "${Tmp_params}"

}

Log_check() {
	Conf=/etc/syslog.conf
	[[ ! -f ${Conf}"-bkp-$(date +%F)" ]] && cp ${Conf}{,-bkp-$(date +%F)}
	Tmp_params=$(mktemp)
        Log_Params > "${Tmp_params}"
	regex='^[ ^\t\*a-z;.0-9 \t-]*'
        while read  values logfile
        do
	
		if ! grep -qP "${regex}${logfile}" $Conf; then
			newvalue="$(echo -e "${values}\t${logfile}" | expand -t 56)"
			echo sed -i "'\$a ${newvalue}'" $Conf | sh	
			OK "$logfile"
		else
			Exists "Log check for $logfile"
		fi	
		
	done < ${Tmp_params}
	rm -f "${Tmp_params}"

	# for Sudo log
	sudo_conf='/etc/sudoers'
	sudo_log="$( grep -P '^[ ^\t]*Defaults[ ^\t]*logfile' $sudo_conf )"
	sudo_param='Defaults logfile=/var/log/sudo.log'
	if [[ -z $sudo_log ]]; then
		chmod u+w $sudo_conf
		echo sed -i "'\$a ${sudo_param}'" $sudo_conf | sh 
		OK "Updating Sudores"
		chmod u-w $sudo_conf
		touch "/var/log/sudo.log"
	else
	  	logpath="$(cut -d'=' -f2 <<< "${sudo_log}")"
		if [[ "${logpath}" == "/var/log/sudo.log" ]]; then
			Exists "Log check for $logpath"
		else
			search=$(echo $logpath | sed 's/\(\/\)/\\\//g' )
			chmod u+w $sudo_conf
			echo sed -i "'s/$search/\/var\/log\/sudo.log/'" $sudo_conf | sh
			chmod u-w $sudo_conf
			OK "Updating Sudores"
			touch "/var/log/sudo.log"
		fi
	fi
}

Audit_control() {

	Tmp_params=$(mktemp)
        Audit_Perm > "${Tmp_params}"
        while read  f
	do
		[[ ! -f $f ]] && touch $f
		[[ $(stat -c '%a' ${f}) == 600 ]] && Exists "Permission 600 $f" ||
		{ chmod 0600 ${f}; OK "Updated ${f}"; }
	done < ${Tmp_params}
	rm -f ${Tmp_params}

}

User_Set_Perm(){
	Tmp_params=$(mktemp)
	User_Perm > "${Tmp_params}"
	while read file perm owner
	do
		[[ ! -f $file ]] && touch $file
		[[ $(stat -c '%a' ${file}) == ${perm} ]] && Exists "Permission $perm $file" ||
		{ chmod -R ${perm} ${file}; OK "Updated ${file}"; }
		[[ $(stat -c '%u:%g' ${file}) == $owner ]] || chown ${owner} ${file}

	done < ${Tmp_params}
	rm -f ${Tmp_params}
}

Disable_user(){

	Tmp=$(mktemp)
	Disable_Users_list > "${Tmp}"
	PassFile='/etc/passwd'
	BkpPassdb=${PassFile}-bkp-$(date +%F)
	[[ ! -f $BkpPassdb ]] && cp $PassFile $BkpPassdb
	while read user
	do
		if	grep -qP "^${user}" $PassFile; then
		 	
			grep -qP "^#[ ^\t]*""${user}" $PassFile && { Exists "User $user already Disable"; continue; }
			sed -i "s/^$user/# $user/" $PassFile
			OK "Disableing User $user"
		else
			Exists "User $user already Disable"
		fi
		
			

	done < ${Tmp}
	rm -f ${Tmp}

}

Disable_Group() {
	GrpFile='/etc/group'
        Bkpgrpdb=${GrpFile}-bkp-$(date +%F)
        [[ ! -f $Bkpgrpdb ]] && cp $GrpFile $Bkpgrpdb

	for g in "${Disable_Groups_list[@]}"; 
	do
		
		if      grep -qP "^${g}" $GrpFile; then

                        grep -qP "^#[ ^\t]*""${g}" $GrpFile && { Exists "Group $g already Disable"; continue; }
                        sed -i "s/^$g/# $g/" $GrpFile
                        OK "Disableing Group $g"
                else
                        Exists "Group $g already Disable"
                fi

		
	done


}

Service_Control(){

	ServiceList=$(mktemp)
	SystemServiceList > $ServiceList
	while read srv option
	do
		 srvpath="/etc/init.d/$srv"
		if [[ ! -f $srvpath ]]; then
			Warning "$srv Service not exists"
			continue
		elif [[ $option == "enable" ]]; then
			/etc/init.d/$srv start >/dev/null 2>&1
			chkconfig --level 2345 $srv on 
		elif [[ $option == "disable" ]]; then
			
			if /etc/init.d/$srv status >/dev/null 2>&1
			then
				echo "$srv Service currently Running..."
				echo -e "Do you want really stop this service (Yes/No)?(n):" 
				read -s ans 
				case $ans in 
					[yY]|[yY][eE][sS]) /etc/init.d/$srv stop
							   chkconfig $srv off ;;
					[nN]|[nN][oO])	continue ;;
					#	*)	continue ;;
				esac
			fi
		fi

	done < $ServiceList
	rm -f $ServiceList


}


#------------------------{ Main Program}-----------------------------------------
while ((TST>0))
do
Show_menu
read input
	case $input in

		1)  echo  "Select SSH"
			SSH_Security_check	;;
		2)  echo  "TCP Wrapper"
			TCPWrapper_check 	;;
		3)  echo  "FileSystem Security Check"
			FileSystemChecks	;;
		4)  echo  "Kernel Level Security"
			Kernel_Tuning		;;
		5)  echo  "Log & audit control"
			Log_check		;
			Audit_control		;
			User_Set_Perm		;
			Disable_user		;
			Disable_Group		;
						;;
		6)  echo "Service Control"	;
			Service_Control		;;

		*)  echo "unknown Options... "; 
	esac
Sub_menu
read input
	case $input in
		1) TST=1
						;;
		2) TST=0
						;;
	esac
done
