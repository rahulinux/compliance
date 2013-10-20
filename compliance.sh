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
		on) chattr +i $conf ;;
		off) chattr -i $conf ;;
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
        exist_or_not=$( echo "{values}" |\
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

}


#------------------------{ Main Program}-----------------------------------------
while ((TST>0))
do
Show_menu
read input
	case $input in

		1)  echo -e "Select SSH\n"
			SSH_Security_check	;;
		2)  echo -e "TCP Wrapper\n"
			TCPWrapper_check 	;;
		3)  echo -e "FileSystem Security Check\n"
			FileSystemChecks	;;
		4)  echo -e "Kernel Level Security\n"
			Kernel_Tuning		;;

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
