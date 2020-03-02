#!/bin/bash 
#set -x
#trap read debug
#Devel made by Leandro Rocha for the ISP FNC.
#The need is to form a properly tool to provisioning the ONU's from Nokia in the right way.
 
#Ver 0.6.1 - 02/03/2020 - Fix log variable and code.
#Ver 0.6 - 28/02/2020 - Update almost everything in the script. Incremented new functions, factory reset options.
#Ver 0.5 - 27/02/2020 - Add function and validation
#Ver 0.4 - 19/02/2020 - Add log only for inputs.
#Ver 0.3 - 12/02/2020 - Fix Some bugs, more intuitive perspective for users.
#Ver 0.2 - 10/02/2020 - User Interaction, validation, Wireless 2g && 5G and IPv6 Config, first release for employers use.
#Ver 0.1 - 07/02/2020 - Begin the dev
 
#wifi_name=$1
#wifi_password=$2
username="usermaster"
password="masteruser"
history_dir="/var/log/ont-nokia/log.txt"
#ppp_user=$3
#ppp_password=$4
#ppp_vlan=$5
 
date_atual=$(date +%d-%m-%Y"_"%H:%M:%S)

user_input () {

	#User Interation 
	echo  "Bem vindo ao utilitario para configuração de ONU's da Nokia/China Telecom!"
	echo -n "Digite o usuario PPP do cliente: "
	read ppp_user
	(( ${#ppp_user} < 4 )) && echo "Favor digitar um usuario válido." && read -p "Precione qualquer tecla para finalizar o programa." && exit
	echo -n "Digite a senha PPP do cliente: "
	read ppp_password
	(( ${#ppp_password} < 4 )) && echo "Favor digitar uma senha válida." && read -p "Precione qualquer tecla para finalizar o programa." && exit
	echo -n "Digite a vlan do cliente: "
	read ppp_vlan
	! (( $ppp_vlan > 10  &&  $ppp_vlan < 4095 )) && echo "Favor digitar uma vlan válida." && read -p "Precione qualquer tecla para finalizar o programa." && exit
	echo -n "Digite o ssid do wi-fi do cliente: "
	read wifi_name
	! (( ${#wifi_name} > 3 && ${#wifi_name} < 12 )) && echo "Favor digitar um ssid valido." && read -p "Precione qualquer tecla para finalizar o programa." && exit
	echo -n "Digite a senha do wi-fi do cliente: "
	read wifi_password
	(( ${#wifi_password} < 8 )) && echo "Favor digitar uma senha para o wi-fi valida." && read -p "Precione qualquer tecla para finalizar o programa." && exit

	echo -e "As informacoes digitadas foram:\n Usuario PPP: $ppp_user \n Senha PPP: $ppp_password \n Vlan: $ppp_vlan \n SSID Wi-fi: $wifi_name \n Wi-fi password: $wifi_password"
	echo -e "\n Deseja confirmar elas? ( S / N )"
	read confirmacao
	[[ $confirmacao = "N" || $confirmacao = "n" ]] && echo "Favor rodar o programa novamente." && read -p "Precione qualquer tecla para finalizar o programa." && exit
	 
}
 
ont_icmp_validation () {


	conn_test=$(fping 192.168.1.1)
	 
	#Login Curl
	[[ "$conn_test" =~ "unreachable" ]] && echo "Sem conectividade com o roteador, favor verificar o cabo de rede." && read -p "Precione qualquer tecla para finalizar o programa." && exit
	 
}

ont_factory_reset_telnet () {

cmd=$(/usr/bin/expect <(cat << EOF
spawn telnet 192.168.1.1
sleep 5
expect "#"
send "cfgcli -r \r"
sleep 0.5
expect "#"
send "reboot\r"
expect "#"
EOF
)
)

}

ont_login () {

ont_login_username=$1
ont_login_password=$2

	cmd=$(curl -s -c test.txt -d "name=$ont_login_username" -d "pswd=$ont_login_password" http://192.168.1.1/login.cgi)
	if [[ "$cmd" =~ "already login in" ]];then 

		echo "Usuário já se encontra logado, for realizar o logoff do mesmo." 
		read -p "Precione qualquer tecla para finalizar o programa."
		exit
 
 	elif [[ "$cmd" =~ "error username or password" ]]; then

 		echo "Usuário e senha incorreto. - $ont_login_username / $ont_login_password"
 		ont_login_output="2"

 	elif [[ -z "$cmd" ]]; then

	 	echo "Login efetuado sucesso."
	 	ont_login_output="3"

fi

}

ont_factory_reset () {

	ont_factory_reset_array=( $username/$password telecomadmin/admintelecom )
	for cred in "${ont_factory_reset_array[@]}"; do
		
	    ont_factory_reset_user=$(echo $cred | awk -F "/" '{print $1}')
        ont_factory_reset_pass=$(echo $cred | awk -F "/" '{print $2}')
		echo "Realizando login para resetar o ativo - $ont_factory_reset_user / $ont_factory_reset_pass."
		ont_login $ont_factory_reset_user $ont_factory_reset_pass

		if [[ $ont_login_output == "3" ]]; then

		 	cmd=$(curl -s 'http://192.168.1.1/system.cgi?telnet+on' -H 'Referer: http://192.168.1.1/system.cgi?telnet' -b test.txt --data 'data' --compressed --insecure)
		 	echo "Efetuando o factory reset."
		 	ont_factory_reset_telnet
		 	echo "Factory Reset concluido, favor aguardar 3 minutos e rodar o programa novamente."
		 	read -p "Precione qualquer tecla para finalizar o programa." && exit

		fi
	
	done
}
 
ont_configuration () {

	#Enabling Telnet
	cmd=$(curl -s 'http://192.168.1.1/system.cgi?telnet+on' -H 'Referer: http://192.168.1.1/system.cgi?telnet' -b test.txt --data 'data' --compressed --insecure)
	 
	echo "Habilitando Telnet..."
	 
	#curl -s -b test.txt http://192.168.1.1/login.cgi?out
	cmd=$(curl -s -b test.txt http://192.168.1.1/login.cgi?out)
	 
	 

	echo "Adicionando configurações adicionais."
	wifi_name_modified=$(echo fastnet-$wifi_name)

	#IPv6, Wifi, Remote Access
	#Expect for Telnet
cmd=$(/usr/bin/expect <(cat << EOF
spawn telnet 192.168.1.1
sleep 5
expect "#"
send "cfgcli -s InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.Password $password\r"
sleep 0.3
expect "#"
send "cfgcli -s InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.UserName $username\r"
sleep 0.3
expect #
send "cfgcli -f -s InternetGatewayDevice.DeviceInfo.X_CT-COM_IPProtocolVersion.Mode 3\r"
sleep 0.3
expect "#"
send "cfgcli -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID $wifi_name_modified-2G\r"
sleep 0.3
expect "#"
send "cfgcli -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID $wifi_name_modified-5G\r"
sleep 0.3
expect "#"
send "cfgcli -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey $wifi_password\r"
sleep 0.3
expect "#"
send "cfgcli -s InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1.PreSharedKey $wifi_password\r"
sleep 0.3
expect "#"
send "cfgcli -f -s InternetGatewayDevice.X_ASB_COM_PreConfig.X_ASB_COM_ExternalWebAccess true\r"
sleep 0.3
expect "#"
send "cfgcli -s InternetGatewayDevice.X_ASB_COM_AppCfg.HttpdCfg.NetworkAccess WAN\r"
sleep 0.5
EOF
)
)
	
	#pppoe
	 
	#curl -s -c test.txt -d 'name=telecomadmin' -d 'pswd=admintelecom' http://192.168.1.1/login.cgi
	 
	#Log In with new user
	curl -s -c test.txt -d "name=$username" -d "pswd=$password" http://192.168.1.1/login.cgi
	 
	 
	 
	echo "Configurando PPP."
	#Config the PPP
	curl 'http://192.168.1.1/wan_config.cgi?config' -H 'Referer: http://192.168.1.1/wan_config.cgi' -b test.txt --data "conn_id=0&conn_type=pppoe&servlist=INTERNET&conn_mode=R&ipv=3&pppoe_username=$ppp_user&pppoe_password=$ppp_password&pppoeswd=1&natSw=on&mtu=1492&dhcp_enable=on&vlanSw=2&vlanId=$ppp_vlan&m8021p=0&b_lan1=1&b_lan2=2&b_lan3=3&b_lan4=4&b_ssid1=1&b_5g_ssid1=5&ip_mode=pppoe&externalIpAddr=&netmask=&defGateway=&firstDns=&secondDns=&ipv6_origin=AutoConfigured&en_prefix=on&ipv6_prefix=PPPoE&ipAddr_v6=&defGw_v6=&prefix_v6=&firstDns_v6=&secondDns_v6=&aftr_mode=0&aftr_addr=&trigger=AlwaysOn&act=&tr69_flag=" --compressed --insecure
	 
	echo "Configurando IPV6."
	#Config IPv6Lan
	curl 'http://192.168.1.1/lan_ipv6.cgi?config' -H 'Referer: http://192.168.1.1/lan_ipv6.cgi' -b test.txt --data 'LanDNS_select=WANConnection&LanPri_DNS_text=&LanSec_DNS_text=&LanDNS_Interface_select=ppp111&LanPrefix_select=WANDelegated&LanPrefix_text=&LanInterface_select=ppp111&LanStartAddress_text=0%3A0%3A0%3A2&LanEndAddress_text=0%3A0%3A0%3A255&LanOtherInfo_checkbox=&LanMaxRA_text=600&LanMinRA_text=200' --compressed --insecure
	 
	echo "Configurando WLAN 2G."
	#Config Wlan 2G
	curl 'http://192.168.1.1/wlan_config.cgi?do_config_all' -H 'Referer: http://192.168.1.1/wlan_config.cgi' -b test.txt --data "ap_enable=on&ssidx=1&ssid_enable=on&ssid=$wifi_name-2G&wl_beaconType=WPA%2FWPA2&wep_encrypt=Both&wepKeyBit=40-bit&wpa_encrypt_mode=TKIPandAESEncryption&wpa_psk=$wifi_password&wl_channel=0&wl_mode=n&wl_NChannelwidth=0&wl_N_GuardInterval=0&wl_power=100" --compressed --insecure
	 
	echo "Configurando WLAN 5G."
	#Config Wlan 5G
	curl 'http://192.168.1.1/wlan_config.cgi?do_config_11ac_all' -H 'Referer: http://192.168.1.1/wlan_config.cgi?config_11ac' -b test.txt --data "ap_enable=on&ssidx=5&ssid_enable=on&ssid=$wifi_name-5G&wl_beaconType=WPA%2FWPA2&wep_encrypt=Both&wepKeyBit=40-bit&wpa_encrypt_mode=TKIPandAESEncryption&wpa_psk=$wifi_password&wl_channel=0&wl_NChannelwidth=3&wl_N_GuardInterval=0&wl_power=100" --compressed --insecure
	 
	echo "Desabilitando telnet e salvando as configurações."
	#Disabling Telnet
	cmd=$(curl -s 'http://192.168.1.1/system.cgi?telnet+off' -H 'Referer: http://192.168.1.1/system.cgi?telnet' -b test.txt --data 'data' --compressed --insecure)
	#Logout
	cmd=$(curl -s -b test.txt http://192.168.1.1/login.cgi?out)


	 
	echo -e "$date_atual \n| PPP Name:$ppp_user - PPP Password: $ppp_password - PPP_VLAN: $ppp_vlan - Wifi Name: $wifi_name - Wifi Password: $wifi_password\n" >> $history_dir
	 
	read -p "Programa executado sem erros." 

}



ont_validation () {

	echo -e "Validando usuário e senha."
	ont_login $username $password 
	#Case the login is incorrectly
	[[ $ont_login_output == "2" ]] && echo "Equipamento será resetado." && read -p "Precione qualquer tecla para continuar." && ont_factory_reset

	#Login 
	#Log In with new user
	#curl -s -c test.txt -d "name=$username" -d "pswd=$password" http://192.168.1.1/login.cgi
	#Wan output
	curl -s 'http://192.168.1.1/wan_config.cgi' -b test.txt > output_wan.txt

	#Wlan Output
	curl -s 'http://192.168.1.1/wlan_config.cgi' -b test.txt > output_wlan.txt
	
	#Login Out
	cmd=$(curl -s -b test.txt http://192.168.1.1/login.cgi?out)
	#PPP
	cmd=$(cat output_wan.txt | grep "Username:'" | tr -d , | awk -F "'" '{print $2}')
	[[ "$cmd" != "$ppp_user" ]] && output_validation=$(echo "\nPPP Incorreto - $cmd") && error_var=($error_var + 1)

	#VLAN
	cmd=$(cat output_wan.txt | grep VLANIDMark: | head -n1 | tr -d , | awk -F ':' '{print $2}')
	[[ "$cmd" != "$ppp_vlan" ]] && output_validation=$(echo "\nVLAN Incorreta - $cmd") && error_var=($error_var + 1)

	#Wireless
	cmd=$(cat output_wlan.txt |  grep "SSID:'" | tr -d , | awk -F "'" '{print $2}')
	[[ "$cmd" != "$wifi_name" ]] && output_validation=$(echo "\nWLAN Incorreta - $cmd") && error_var=($error_var + 1)

	if [[ $error_var > 0 ]]; then
		echo "$output_validation"
		#echo "Equipamento sera resetado."
		#output_val_end="1"
	else
		echo "Não foram encontrados erros nas configurações do equipamento." 
		read -p "Precione qualquer tecla para finalizar o programa." 
		exit
	fi

}
 


#Begin with User Input 
user_input 

#ICMP Validation
ont_icmp_validation

#Validation of the input
ont_login telecomadmin admintelecom

#Case the login is incorrectly
[[ $ont_login_output == "2" ]] && echo "Equipamento será resetado." && read -p "Precione qualquer tecla para continuar." && ont_factory_reset


#Config into the ONT
ont_configuration

#Val Configuration
ont_validation

