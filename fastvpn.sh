#!/usr/bin/env bash

export PATH=$PATH:/bin:/usr/bin:/usr/local/bin:/usr/sbin
cur_path=`cd "$(dirname "$0")"; pwd`    # /root
cur_sys=`cat /etc/*-release | sed -r "s/^ID=(.*)$/\\1/;tA;d;:A;s/^\"(.*)\"$/\\1/" | tr -d '\n'` #centos
local_ip=`hostname -I | cut -d' ' -f1`
external_ip=`curl https://ipv4.gdt.qq.com/get_client_ip 2>/dev/null`

# Stop the script when any errors occur
set -e && clear
stty erase ^H

_color_red='\E[1;31m'
_color_green='\E[1;32m'
_color_yellow='\E[1;33m'
_color_blue='\E[1;34m'
_color_wipe='\E[0m'

function print_err() {
    # $1 msg string
    # $2 special tag
    _tmp_status=${2:-Error}
    printf "[${_color_red} ${_tmp_status} ${_color_wipe}] ${1}\n"
}

function print_success() {
    _tmp_status=${2:-Success}
    printf "[${_color_green} ${_tmp_status} ${_color_wipe}] ${1}\n"
}

# check user
[[ $EUID -ne 0 ]] && print_err "Root User check failed"

# check linux version
{
    source /etc/os-release || /bin/true
    if [[ "${ID}" =~ ^(centos|rhel)$ ]]; then
        if [[ "${VERSION_ID}" =~ ^7 || "${VERSION_ID}" =~ ^8 ]]; then
            print_success "Operating system is ${ID}-${VERSION_ID}"
        fi
    else
        print_err "Non Centos and Rhel operating systems are not supported" && exit 1
    fi
}

# check arch
test $(getconf LONG_BIT) -ne 64 && print_err "Only 64 bit Linux operating system is supported"

function print_warning() {
    _tmp_status=${2:-Warning}
    printf "[${_color_yellow} ${_tmp_status} ${_color_wipe}] ${1}\n"
}

function print_info() {
    _tmp_status=${2:-Info}
    printf "[${_color_blue} ${_tmp_status} ${_color_wipe}] ${1}\n"
}

function prepare_stage()
{
    print_info "Install Openvpn Easy-rsa Package"
    yum -y install openvpn easy-rsa &>/dev/null
    if test $? -ne 0; then
    	yum install epel-release -y
        yum makecache
    fi
    yum -y install openvpn easy-rsa &>/dev/null
    if test $? -ne 0; then
        print_err "No rpm package openvpn or easy-rsa"
    fi

    print_info "Copy Easy-rsa to /etc/openvpn dir"
    cp -vR /usr/share/easy-rsa/3.0/ /etc/openvpn/easy-rsa

    print_info "Generate Vars Env for vpn"
    read -p $'Your Country: \n' country
    read -p $'Your Province: \n' province
    read -p $'Your City: \n' city
    read -p $'Your Org: \n' org
    read -p $'Your Ou: \n' ou
    cat > /etc/openvpn/easy-rsa/vars <<EOF
set_var EASYRSA_REQ_COUNTRY     $country
set_var EASYRSA_REQ_PROVINCE    $province
set_var EASYRSA_REQ_CITY        $city
set_var EASYRSA_REQ_ORG         $org
set_var EASYRSA_REQ_OU          $ou
EOF
}

function server_ca_key()
{
    print_info "初始化"
    cd /etc/openvpn/easy-rsa && pwd -P
    ./easyrsa init-pki
    print_info "创建根证书并设置密码"
    ./easyrsa build-ca
    print_info "创建服务端证书"
    ./easyrsa gen-req server nopass
    print_info "签约服务端证书"
    ./easyrsa sign server server
    print_info "创建Diffie-Hellman，确保key穿越不安全网络的命令"
    ./easyrsa gen-dh
}

function client_ca_key()
{
    cp -vR /usr/share/easy-rsa/3.0/ /etc/openvpn/${client_name}
    cd /etc/openvpn/${client_name} && pwd -P && print_info "初始化"
    ./easyrsa init-pki
    print_info "创建客户端key及生成证书"
    ./easyrsa gen-req ${client_name}
    cd /etc/openvpn/easy-rsa && pwd -P
    print_info "导入req文件"
    ./easyrsa import-req /etc/openvpn/${client_name}/pki/reqs/${client_name}.req ${client_name}
    print_info "签约证书"
    ./easyrsa sign client ${client_name}
}

function generate_server_conf()
{
    print_info "开始生成服务端配置文件"
    read -p $'请设置监听地址: [推荐 0.0.0.0]\n' local
    read -p $'端口: [推荐 1194]\n' port
    read -p $'地址池: [推荐 10.20.x.0]\n' server_pool
    read -p $'子网网段: [例 192.168.1.0]\n' server_subnet
    read -p $'子网掩码:\n' server_mask
    read -p $'DNS: [推荐 114.114.114.114]\n' server_dns
    cat > /etc/openvpn/server/server.conf <<EOF
local ${local}   # 监听地址
port ${port}       # 监听端口
proto udp       # 监听协议
dev tun         # 采用路由隧道模式
ca /etc/openvpn/easy-rsa/pki/ca.crt  # ca证书路径
cert /etc/openvpn/easy-rsa/pki/issued/server.crt    #服务器证书
key /etc/openvpn/easy-rsa/pki/private/server.key     # 服务器秘钥
dh /etc/openvpn/easy-rsa/pki/dh.pem  # 密钥交换协议文件
server ${server_pool} 255.255.255.0  # 给客户端分配地址池，注意：不能和VPN服务器内网网段有相同
ifconfig-pool-persist ipp.txt
push "route ${server_subnet} ${server_mask}"    # 这里要改改，如果想要通过客户端访问服务器的内网IP时候
push "dhcp-option DNS ${server_dns}"     # 推送DNS自定义的
client-to-client        # 客户端之间的通信
keepalive 10 120 # 存活时间，10秒ping一次,120 如未收到响应则视为断线
comp-lzo        #传输数据压缩
max-clients 100 #最多允许 100 客户端连接
user openvpn    #用户
group openvpn   #用户组
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append  /var/log/openvpn/openvpn.log
verb 3
mute 20
EOF
}

function generate_client_conf()
{
    read -p $'输入远程VPN服务器地址或域名:[默认为本机IP]\n' server_addr
    server_addr=${server_addr:-${external_ip}}
    read -p $'输入远程VPN服务器端口:\n' server_port
    cat >/etc/openvpn/client/${client_name}.conf<<EOF
client
dev tun
proto udp   # 根据自己需要改
remote ${server_addr} ${server_port} # 根据自己需要改，可以改成域名的 端口
resolv-retry infinite
nobind
persist-key
persist-tun
mute-replay-warnings
remote-cert-tls server
cipher AES-256-CBC
comp-lzo
verb 3
<ca>
`cat /etc/openvpn/easy-rsa/pki/ca.crt`
</ca>
<cert>
$(sed -n '/BEGIN/,/END/p' /etc/openvpn/easy-rsa/pki/issued/${client_name}.crt)
</cert>
<key>
$(cat /etc/openvpn/${client_name}/pki/private/${client_name}.key)
</key>
EOF
}

function start_server()
{
    print_info "创建日志目录并分配权限"
    mkdir /var/log/openvpn
    chown -R openvpn:openvpn /var/log/openvpn
    chown -R openvpn:openvpn /etc/openvpn
    print_info "配置防火墙规则"
    iptables -t nat -A POSTROUTING -s ${server_pool}/24 -j MASQUERADE
    service iptables save
    print_info "配置Linux转发规则"
    if test `sysctl net.ipv4.ip_forward | grep 0` -eq 0; then
        sed -i '$a net.ipv4.ip_forward = 1\n' /etc/sysctl.conf
        $? -eq 0 && sysctl -p
    fi
    print_info "启动VPN服务"
    systemctl enable --now openvpn-server@server.service
}

function start_client()
{
    read -p $'该客户端VPN文件是用于Linux还是win平台?[linux/win]\n' platform
    case ${platform} in
        "linux")
            print_success "VPN文件位置: /etc/openvpn/client/${client_name}.conf"
            break
            ;;
        "win")
            mv /etc/openvpn/client/${client_name}.{conf,ovpn}
            print_success "VPN文件位置: /etc/openvpn/client/${client_name}.ovpn"
            break
            ;;
        *)
            start_client
            ;;
    esac
}

function install_VPN_Server()
{
    print_info "Prepare Stage"
    prepare_stage
    server_ca_key
    generate_server_conf
    start_server
}

function generate_VPN_Client()
{
    client_ca_key
    generate_client_conf
    start_client
}

function parse_run() {
    print_info "parsing entry"
    _tmp_list=(
        install_VPN_Server
        generate_VPN_Client
        uninstall_VPN
    )

    print_info "please select function"

    select _v in ${_tmp_list[@]}; do
        case ${_v} in
            "install_VPN_Server")
                install_VPN_Server
                print_success "VPN 服务器端部署成功"
                break
                ;;
            "generate_VPN_Client")
                read -p $'指定客户端名称\n' client_name
                generate_VPN_Client
                print_success "VPN 客户端生成成功"
                break
                ;;
            "uninstall_VPN")
                uv
                break
                ;;
            *)
                print_err "不支持的选项"
                print_info "请选择一项要执行的操作"
                ;;
        esac
    done
}


parse_run
