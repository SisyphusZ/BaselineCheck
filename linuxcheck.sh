#!/bin/bash
echo "基线核查工具"
echo "Author:Sisyphus"
#----------使用说明----------
#0.创建一个新目录，将该程序的所有文件放入该目录下
#一定要新建一个专门的目录执行该程序，该程序具有一定破坏性，一定要在一个单独的目录下运行
#一定要在单独的目录下运行！一定要在单独的目录下运行！一行要在单独的目录下运行！

#1.apt安装依赖包
#apt-get install clamav
#apt-get install gawk
#apt-get install expect

#2.附加执行权限
#chmod ugo+x linuxcheck.sh

#3.执行程序
#./linuxcheck.sh

#4.可以根据执行需要设置周期计划任务

#5.执行结果存放在当前目录下

#----------使用说明----------

#----------读取配置文件----------
config=`cat ./config.conf`
carID=`echo $config | awk -F "[:]" '{print $1}'`
targetfilepath = `echo $config | awk -F "[:]" '{print $2}'`
#----------读取配置文件结束----------

#----------初始化操作----------
current=`date "+%Y-%m-%d %H:%M:%S"`
timeStamp=`date -d "$current" +%s`
#将current转换为时间戳，精确到毫秒
currentTimeStamp=$((timeStamp*1000+`date "+%N"`/1000000))
#carID=1
ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')
#filepath="."
#check_result="./${ipadd}_${date}/check_result/"
#danger_file="./${ipadd}_${date}/danger_file.txt"
#tmp_file="./${ipadd}_${date}/tmp_file.txt"
#log_file="/tmp/${ipadd}_${date}/log/"
#rm -rf $check_file
#rm -rf $danger_file
#rm -rf log_file
#mkdir ./${ipadd}_${date}/
#mkdir $check_result
tmp_file="./tmp_file.txt"
#mkdir $log_file
#cd $check_file

if [ $(whoami)!="root" ];then
	echo "安全检查必须使用root账号,否则某些项无法检查"
	exit 1
fi

#saveresult="tee -a ./${ipadd}_${date}/check_result/${carID}_result.log"
#savewarning="tee -a ./${ipadd}_${date}/check_result/${carID}_warning.log"

saveresult="tee -a ./${carID}_result.log"
savewarning="tee -a ./${carID}_warning.log"
savetmp="tee -a ./tmp_file.txt"


#----------初始化操作结束----------



#----------向日志中写入车辆信息和时间戳----------
echo "$carID:$currentTimeStamp:NULL;" | $saveresult | $savewarning
printf "\n" | $saveresult
#----------向日志中写入车辆信息和时间戳结束----------

#-----------检查工作环境----------
other_file=$(ls | grep -Ev "1_result.log|1_warning.log|clam.log|checkrules|linuxcheck.sh|hosts.txt|put.exp|config.conf")
if [ -n "$other_file" ];then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!该程序具有破坏性!!!!!!!!!"
    echo "!!!请单独创建一个目录运行该程序!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    exit 1
fi
#----------检查工作环境---------

#----------获取IP信息----------
echo "[OK]:正在检查IP地址.....:NULL;" | $saveresult
ip=$(ifconfig -a | grep -w inet | awk '{print $2}')
if [ -n "$ip" ];then
	(echo "[INFO]:本机IP地址信息:" && echo "$ip" && echo ";")  | $saveresult
else
	echo "[INFO]:本机未配置IP地址:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------获取IP信息结束----------

#----------获取版本信息----------
echo "[OK]:正在检查系统内核版本.....:NULL;" | $saveresult
corever=$(uname -a)
if [ -n "$corever" ];then
	(echo "[INFO]:系统内核版本信息:" && echo "$corever" && echo ";") | $saveresult
else
	echo "[INFO]:未发现内核版本信息:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------获取版本信息结束----------

#----------获取ARP表项----------
echo "[OK]:正在查看ARP表项.....:NULL;" | $saveresult
arp=$(arp -a -n)
if [ -n "$arp" ];then
	(echo "[INFO]:ARP表项:" && echo "$arp" && echo ";") | $saveresult
else
	echo "[INFO]:未发现ARP表项:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------获取ARP表项结束----------

#----------检测TCP端口----------
#TCP或UDP端口绑定在0.0.0.0、127.0.0.1、192.168.1.1这种IP上只表示这些端口开放
#只有绑定在0.0.0.0上局域网才可以访问
#1.端口搜集
echo "[OK]:正在检查TCP开放端口.....:NULL;" | $saveresult
listenport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$listenport" ];then
	(echo "[INFO]:该服务器开放TCP端口以及对应的服务:" && echo "$listenport" && echo ";") | $saveresult
else
	echo "[INFO]系统未开放TCP端口:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.检测向互联网或局域网开放的端口
echo "[OK]:正在检查向互联网/局域网开放的TCP端口.....:NULL;" | $saveresult
accessport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$accessport" ];then
	(echo "[LOW]:以下TCP端口面向局域网或互联网开放,请注意!:" && echo "$accessport" && echo ";") | $saveresult ｜$savewarning
else
	echo "[INFO]:端口未面向局域网或互联网开放:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.检测危险端口
echo "[OK]:正在检查TCP高危端口.....:NULL;" | $saveresult
tcpport=`netstat -anlpt | awk '{print $4}' | awk -F: '{print $NF}' | sort | uniq | grep '[0-9].*'`
count=0
touch $tmp_file
if [ -n "$tcpport" ];then
    for port in $tcpport
    do
        for i in `cat ./checkrules/dangerstcpports.dat`
        do
            tcpport=`echo $i | awk -F "[:]" '{print $1}'`
            desc=`echo $i | awk -F "[:]" '{print $2}'`
            process=`echo $i | awk -F "[:]" '{print $3}'`
            if [ $tcpport == $port ];then
                echo "$tcpport,$desc,$process" | $savetmp
                count=count+1
            fi
        done
    done
fi
if [ $count = 0 ];then
    echo "[INFO]:未发现TCP危险端口:NULL;" | $saveresult
else
    echo "[MEDIUM]:请人工对TCP危险端口进行关联分析与确认:" | $savewarning | $saveresult
    for i in `cat $tmp_file`
    do
        echo $i | $savewarning | $saveresult
    done
    echo ";" |  $savewarning | $saveresult
fi
rm -f $tmp_file
printf "\n" | $saveresult
#----------检测TCP端口结束----------

#---------UDP端口----------
#1.检测TCP端口
echo "[OK]:正在检查UDP开放端口.....:NULL;" | $saveresult
udpopen=$(netstat -anlup | awk  '{print $4,$NF}'|grep : | sed 's/0\.0\.0\.0/::/g' | sed 's/:/ /g' |awk '{print $1,$2}' |sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$udpopen" ];then
	(echo "[INFO]:该服务器开放UDP端口以及对应的服务:" && echo "$udpopen" && echo ";") | $saveresult
else
	echo "[INFO]:系统未开放UDP端口:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.检测向互联网或局域网开放的端口
echo "[OK]:正在检查向互联网/局域网开放的UDP端口.....:NULL;" | $saveresult
udpports=$(netstat -anlup | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
if [ -n "$udpports" ];then
	echo "[LOW]:以下UDP端口面向局域网或互联网开放:" | $saveresult | $savewarning
	for port in $udpports
	do
		nc -uz 127.0.0.1 $port
		if [ $? -eq 0 ];then
			echo "$port"  | $saveresult | $savewarning
		fi
	done
    echo ";"  | $saveresult | $savewarning
else 
	echo "[INFO]:未发现在UDP端口面向局域网或互联网开放:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.检测危险端口
echo "[OK]:正在检查UDP高危端口.....:NULL;" | $saveresult
touch $tmp_file
udpport=`netstat -anlpu | awk '{print $4}' | awk -F: '{print $NF}' | sort | uniq | grep '[0-9].*'`
count=0
if [ -n "$udpport" ];then
	for port in $udpport
	do
		for i in `cat ./checkrules/dangersudpports.dat`
		do
			udpport=`echo $i | awk -F "[:]" '{print $1}'`
			desc=`echo $i | awk -F "[:]" '{print $2}'`
			process=`echo $i | awk -F "[:]" '{print $3}'`
			if [ $udpport == $port ];then
				echo "$udpport,$desc,$process" | $savetmp
				count=count+1
			fi
		done
	done
fi
if [ $count = 0 ];then
	echo "[INFO]:未发现UDP危险端口:NULL;" | $saveresult
else
	echo "[MEDIUM]:请人工对UDP危险端口进行关联分析与确认:" | $saveresult | $savewarning
    for i in `cat $tmp_file`
    do
        echo $i | $savewarning | $saveresult
    done
    echo ";" | $savewarning | $saveresult
fi
printf "\n" | $saveresult
rm -f $savetmp

#---------UDP端口检测结束----------

#---------检测网络连接状况----------
echo "[OK]:正在检查网络连接情况.....:NULL;" | $saveresult
netstat=$(netstat -anlp | grep ESTABLISHED)
netstatnum=$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -n "$netstat" ];then
	(echo "[INFO]:网络连接情况:" && echo "$netstat" && echo ";") | $saveresult
	if [ -n "$netstatnum" ];then
		(echo "[INFO]:网络连接数量如下:" && echo "$netstatnum" && echo ";") | $saveresult
	fi
else
	echo "[INFO]:未发现网络连接:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------网络连接状况检查结束----------

#----------检测网卡模式----------
#1.检测网卡模式
echo "[OK]:正在检查网卡模式.....:NULL;" | $saveresult
ifconfigmode=$(ifconfig -a | grep flags | awk -F '[: = < >]' '{print "网卡:",$1,"模式:",$5}')
if [ -n "$ifconfigmode" ];then
	(echo "[INFO]:网卡工作模式如下:" && echo "$ifconfigmode" && echo ";") | $saveresult
else
	echo "[INFO]:未找到网卡模式相关信息,请人工分析:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.检测是否有处于混杂状态的网卡
echo "[OK]:正在分析是否有网卡处于混杂模式.....:NULL;" | $saveresult
Promisc=`ifconfig | grep PROMISC | gawk -F: '{ print $1}'`
if [ -n "$Promisc" ];then
	(echo "[HIGH]:网卡处于混杂模式:" && echo "$Promisc" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现网卡处于混杂模式:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#----------网卡模式检测结束----------

#----------检测启动项----------
echo "[OK]:正在检查系统自启动项.....:NULL;" | $saveresult
systemchkconfig=$(systemctl list-unit-files | grep enabled | awk '{print $1}')
if [ -n "$systemchkconfig" ];then
	(echo "[INFO]:系统自启动项如下:" && echo "$systemchkconfig" && echo ";")  | $saveresult
else
	echo "[INFO]:未发现系统自启动项:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------启动项检查完毕----------

#----------检查定时任务----------
#1.检测系统定时任务
echo "[OK]:正在分析系统定时任务.....:NULL;" | $saveresult
syscrontab=$(more /etc/crontab | grep -v "# run-parts" | grep run-parts)
if [ -n "$syscrontab" ];then
	(echo "[INFO]:发现存在系统定时任务:" && more /etc/crontab && echo ";") | $saveresult
else
	echo "[INFO]:未发现系统定时任务:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.检测可疑系统定时任务
echo "[OK]:正在分析系统可疑任务.....:NULL:" | $saveresult
dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))"  /etc/cron*/* /var/spool/cron/*)
if [ $? -eq 0 ];then
	(echo "[DANGER]:发现下面的定时任务可疑,请注意！！！" && echo "$dangersyscron" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现可疑系统定时任务:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.检测用户定时任务
echo "[OK]:正在查看用户定时任务.....:NULL:" | $saveresult
crontab=$(crontab -l)
if [ $? -eq 0 ];then
	(echo "[INFO]:发现用户定时任务如下:" && echo "$crontab" && echo ";") | $saveresult
else
	echo "[INFO]:未发现用户定时任务:NULL:"  | $saveresult
fi
printf "\n" | $saveresult

#4.分析可疑的用户定时任务
echo "[OK]:正在分析可疑用户定时任务.....:NULL:" | $saveresult
danger_crontab=$(crontab -l | egrep "((chmod|useradd|groupadd|chattr)|((wget|curl).*\.(sh|pl|py)))")
if [ $? -eq 0 ];then
	(echo "[DANGER]:发现可疑定时任务,请注意:" && echo "$danger_crontab" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现可疑定时任务:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#----------路由表和路由转发----------
#1.获取路由表信息
echo "[OK]:正在检查路由表.....:NULL:" | $saveresult
route=$(route -n)
if [ -n "$route" ];then
	(echo "[INFO]:路由表如下:" && echo "$route" && echo ";") | $saveresult
else
	echo "[INFO]:未发现路由器表:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.检测路由转发功能
echo "[OK]:正在分析是否开启转发功能.....:NULL;" | $saveresult
ip_forward=`more /proc/sys/net/ipv4/ip_forward | gawk -F: '{if ($1==1) print "1"}'`
if [ -n "$ip_forward" ];then
	echo "[LOW]:该服务器开启路由转发,请注意:NULL;" | $savewarning | $saveresult
else
	echo "[INFO]:该服务器未开启路由转发:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------路由表和路由转发结束----------

#----------关键文件检查----------
#1.DNS文件检查
echo "[OK]:正在检查DNS文件.....:NULL:" | $saveresult
resolv=$(more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}') 
if [ -n "$resolv" ];then
	(echo "[INFO]:该服务器使用以下DNS服务器:" && echo "$resolv" && echo ";") | $saveresult
else
	echo "[INFO]:未发现DNS服务器:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.hosts文件
echo "[OK]:正在检查hosts文件.....:NULL;" | $saveresult
hosts=$(more /etc/hosts)
if [ -n "$hosts" ];then
	(echo "[INFO]:hosts文件如下:" && echo "$hosts" && echo ";") | $saveresult
else
	echo "[INFO]:未发现hosts文件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.ssh的公钥文件
echo "[OK]:正在检查公钥文件.....:NULL;" | $saveresult
if [  -e /root/.ssh/*.pub ];then
	echo "[LOW]:发现公钥文件,请注意:NULL;"  | $savewarning | $saveresult
else
	echo "[INFO]:未发现公钥文件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#4.ssh私钥文件
echo "[OK]:正在检查私钥文件.....:NULL;" | $saveresult
if [ -e /root/.ssh/id_rsa ];then
	echo "[LOW]:发现私钥文件,请注意:NULL;" | tee -a $danger_file | $saveresult
else
	echo "[INFO]:未发现私钥文件:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------关键文件检查结束----------

#----------系统当前运行的服务----------
echo "[OK]:正在检查运行服务.....:NULL;" | $saveresult
services=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')
if [ -n "$services" ];then
	(echo "[INFO]:以下服务正在运行:" && echo "$services" && echo ";") | $saveresult
else
	echo "[INFO]:未发现正在运行的服务:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------系统当前运行的服务检查结束----------

#----------用户信息检查----------
# 1.当前登陆用户
echo "[OK]:正在检查正在登录的用户.....:NULL;" | $saveresult
(echo "[INFO]:系统登录用户:" && who && echo ";") | $saveresult
printf "\n" | $saveresult

# 2.用户信息
echo "[OK]:正在查看用户信息.....:NULL;" | $saveresult
echo "[INFO]:用户名 口令 用户标识号 组标识号 注释性描述 主目录 登录Shell:" | $saveresult
more /etc/passwd  | $saveresult
echo ";" | $saveresult
printf "\n" | $saveresult

#3.除root以外的超级用户
echo "[OK]:正在检查是否存在除root用户以外的超级用户.....:NULL;" | $saveresult
Superuser=`more /etc/passwd | egrep -v '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if($3==0) print $1}'`
if [ -n "$Superuser" ];then
	echo "[HIGH]:除root外发现超级用户:" | $savewarning | $saveresult
	for user in $Superuser
	do
		echo $user | $saveresult
		if [ "${user}" = "toor" ];then
			echo "[!!!]BSD系统默认安装toor用户,其他系统默认未安装toor用户,若非BSD系统建议删除该账号" | $saveresult
		fi
	done
    echo ";"
else
	echo "[INFO]:未发现除root用户以外的超级用户:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#4.可登陆用户
echo "[OK]:正在检查可登录的用户......:NULL;" | $saveresult
loginuser=`cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}'`
if [ -n "$loginuser" ];then
	echo "[INFO]:以下用户可以登录:" | $saveresult
	for user in $loginuser
	do
		echo $user | tee -a $danger_file | $saveresult
	done
    echo ";"
else
	echo "[INFO]:未发现可以登录的用户:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#5.非系统用户
echo "[OK]:正在检查非系统本身自带用户:NULL;" | $saveresult
if [ -f /etc/login.defs ];then
	uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
	nosystemuser=`gawk -F: '{if ($3>='$uid' && $3!=65534) {print $1}}' /etc/passwd`
	if [ -n "$nosystemuser" ];then
		(echo "[INFO]:以下用户为非系统本身自带用户:" && echo "$nosystemuser" && echo ";") | $savewarning | $saveresult
	else
		echo "[INFO]:未发现除系统本身外的其他用户:NULL;" | $saveresult
	fi
fi
printf "\n" | $saveresult

#6.空口令且可登陆用户
echo "[OK]:正在检查空口令且可登录的用户.....:NULL;" | $saveresult
aa=$(cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}')
bb=$(gawk -F: '($2=="") {print $1}' /etc/shadow)
cc=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
flag=""
touch $tmp_file
for a in $aa
do
    for b in $bb
    do
        if [ "$a" = "$b" ] && [ -n "$cc" ];then
            echo $a | $savetmp
            flag=1
        fi
    done
done
if [ -n "$flag" ];then
	echo "[HIGH]:存在空口令且可登陆用户:" | $savewarning | $saveresult
    for i in `cat $tmp_file`
    do
        echo $i | $savewarning | $saveresult
    done
    echo ";" | $savewarning | $saveresult
else
	echo "[INFO]:未发现空口令且可登录用户:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#7.用户口令未加密
echo "[OK]:正在检查口令加密用户.....:NULL;" | $saveresult
noenypasswd=$(awk -F: '{if($2!="x") {print $1}}' /etc/passwd)
if [ -n "$noenypasswd" ];then
	(echo "[HIGH]:以下用户口令未加密:" && echo "$noenypasswd" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现口令未加密的用户:NULL;"  | $saveresult
fi
printf "\n" | $saveresult
#----------用户信息分析结束----------

#----------用户组信息检测----------
#1.用户组信息
echo "[OK]:正在检查用户组信息.....:NULL;" | $saveresult
echo "[INFO]:用户组信息如下:"
(more /etc/group | grep -v "^#" | echo ";") | $saveresult
printf "\n" | $saveresult

#2.特权用户组
echo "[OK]:正在检查特权用户组.....:NULL;" | $saveresult
roots=$(more /etc/group | grep -v '^#' | gawk -F: '{if ($1!="root"&&$3==0) print $1}')
if [ -n "$roots" ];then
	echo "[HIGH]:除root用户外root组还有以下用户:" | $savewarning | $saveresult
	for user in $roots
	do
		echo $user | $savewarning | $saveresult
	done
    echo ";"
else 
	echo "[INFO]:除root用户外root组未发现其他用户:NULL" | $saveresult
fi
printf "\n" | $saveresult

#3.相同GID用户
echo "[OK]:正在检查相应GID用户组.....:NULL;" | $saveresult
groupuid=$(more /etc/group | grep -v "^$" | awk -F: '{print $3}' | uniq -d)
if [ -n "$groupuid" ];then
	(echo "[HIGH]:发现相同GID用户组:" && echo "$groupuid" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现相同GID的用户组:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#4.相同用户组名
echo "[OK]:正在检查相同用户组名.....:NULL;" | $saveresult
groupname=$(more /etc/group | grep -v "^$" | awk -F: '{print $1}' | uniq -d)
if [ -n "$groupname" ];then
	(echo "[HIGH]:发现相同用户组名:" && echo "$groupname" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现相同用户组名:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------用户组信息检测结束----------

#----------文件权限检测----------
#1.etc文件权限检测
echo "[OK]:正在检查etc文件权限.....:NULL;" | $saveresult
etc=$(ls -l / | grep etc | awk '{print $1}')
if [ "${etc:1:9}" = "rwxr-x---" ]; then
    echo "[INFO]:/etc/权限为750,权限正常:NULL;" | $saveresult
else
    echo "[MEDIUM]:/etc/文件权限为""${etc:1:9}","权限不符合规划,权限应改为750:NULL;" | $saveresult | $savewarning
fi
printf "\n" | $saveresult

#2.shadow文件权限
echo "[OK]:正在检查shadow文件权限.....:NULL;" | $saveresult
shadow=$(ls -l /etc/shadow | awk '{print $1}')
if [ "${shadow:1:9}" = "rw-------" ]; then
    echo "[INFO]:/etc/shadow文件权限为600,权限符合规范:NULL;" | $saveresult
else
    echo "[MEDIUM]:/etc/shadow文件权限为""${shadow:1:9}"",不符合规范,权限应改为600:NULL;" | $savewarning | $saveresult
fi
printf "\n" | $saveresult

#3.passwd文件权限
echo "[OK]:正在检查passwd文件权限.....:NULL;" | $saveresult
passwd=$(ls -l /etc/passwd | awk '{print $1}')
if [ "${passwd:1:9}" = "rw-r--r--" ]; then
    echo "[INFO]:/etc/passwd文件权限为644,符合规范:NULL;" | $saveresult
else
    echo "[MEDIUM]:/etc/passwd文件权限为""${passwd:1:9}"",权限不符合规范,建议改为644:NULL;" | $savewarning | $saveresult
fi
printf "\n" | $saveresult

#4.group权限
echo "[OK]:正在检查group文件权限.....:NULL;" | $saveresult
group=$(ls -l /etc/group | awk '{print $1}')
if [ "${group:1:9}" = "rw-r--r--" ]; then
    echo "[INFO]:/etc/group文件权限为644,符合规范:NULL;" | $saveresult
else
    echo "[MEDIUM]:/etc/goup文件权限为""${group:1:9}","不符合规范,权限应改为644:NULL;" | $savewarning | $saveresult
fi
printf "\n" | $saveresult

#5.securetty文件权限
echo "[OK]:正在检查securetty文件权限.....:NULL;" | $saveresult
securetty=$(ls -l /etc/securetty | awk '{print $1}')
if [ "${securetty:1:9}" = "-rw-------" ]; then
    echo "[INFO]:/etc/securetty文件权限为600,符合规范:NULL;" | $saveresult
else
    echo "[MEDIUM]:/etc/securetty文件权限为""${securetty:1:9}","不符合规范,权限应改为600:NULL;" | $savewarning | $saveresult
fi
printf "\n" | $saveresult

#6.services文件权限
echo "[OK]:正在检查services文件权限.....:NULL;" | $saveresult
services=$(ls -l /etc/services | awk '{print $1}')
if [ "${services:1:9}" = "-rw-r--r--" ]; then
    echo "[INFO]:/etc/services文件权限为644,符合规范:NULL;" | $saveresult
else
    echo "[MEDIUM]:/etc/services文件权限为""${services:1:9}","不符合规范,权限应改为644:NULL;" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult
#----------文件权限检测结束----------

#----------历史命令检测----------
#1.操作系统历史命令
echo "[OK]:正在检查操作系统历史命令.....:NULL;" | $saveresult
history=$(more /root/.bash_history)
if [ -n "$history" ];then
	(echo "[INFO]:操作系统历史命令如下:" && echo "$history" && echo ";") | $saveresult
else
	echo "[DANGER]:未发现历史命令,请检查是否记录及已被清除:NULL;" | $saveresult ｜ $savewarning
fi
printf "\n" | $saveresult

#2.检测下载命令
echo "[OK]:正在检查是否下载过脚本文件.....:NULL;" | $saveresult
scripts=$(more /root/.bash_history | grep -E "((wget|curl).*\.(sh|pl|py)$)" | grep -v grep)
if [ -n "$scripts" ];then
	(echo "[LOW]:该服务器下载过脚本以下脚本：" && echo "$scripts" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:该服务器未下载过脚本文件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.检测添加账号操作
echo "[OK]:正在检查是否增加过账号.....:NULL;" | $saveresult
addusers=$(more /root/.bash_history | egrep "(useradd|groupadd)" | grep -v grep)
if [ -n "$addusers" ];then
	(echo "[LOW]:该服务器增加过以下账号:" && echo "$addusers" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:该服务器未增加过账号:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#4.检测删除账号操作
echo "[OK]:正在检查是否删除过账号.....:NULL;" | $saveresult
delusers=$(more /root/.bash_history | egrep "(userdel|groupdel)" | grep -v grep)
if [ -n "$delusers" ];then
	(echo "[LOW]:该服务器删除过以下账号:" && echo "$delusers" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:该服务器未删除过账号:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#5.检测可疑命令
echo "[OK]:正在检查历史可疑命令.....:NULL;" | $saveresult
danger_histroy=$(more /root/.bash_history | grep -E "(whois|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)" | grep -v grep)
if [ -n "$danger_histroy" ];then
	(echo "[HIGH]:发现可疑历史命令" && echo "$danger_histroy" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现可疑历史命令:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#6.检测本地文件下载
echo "[OK]:正在检查历史日志中本地下载文件记录.....:NULL;" | $saveresult
uploadfiles=$(more /root/.bash_history | grep sz | grep -v grep | awk '{print $3}')
if [ -n "$uploadfiles" ];then
	(echo "[MEDIUM]:通过历史日志发现本地主机下载过以下文件:" && echo "$uploadfiles" && echo ";") | $saveresult ｜$savewarning
else
	echo "[INFO]:通过历史日志未发现本地主机下载过文件:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------历史命令检测结束----------

#----------检测远程访问控制----------
#1.远程允许策略检测
echo "[OK]:正在检查远程允许策略.....:NULL;" | $saveresult
hostsallow=$(more /etc/hosts.allow | grep -v '#')
if [ -n "$hostsallow" ];then
	(echo "[LOW]:允许以下IP远程访问:" && echo "$hostsallow" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:hosts.allow文件未发现允许远程访问地址:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.远程拒绝策略检测
echo "[OK]:正在检查远程拒绝策略.....:NULL;" | $saveresult
hostsdeny=$(more /etc/hosts.deny | grep -v '#')
if [ -n "$hostsdeny" ];then
	(echo "[LOW]:拒绝以下IP远程访问:" && echo "$hostsdeny" && echo ";") | $saveresult |$savewarning
else
	echo "[INFO]:hosts.deny文件未发现拒绝远程访问地址:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------检测远程访问控制结束----------

#----------密码策略检查----------
#1.密码有效期策略
echo "[OK]:正在检查密码有效期策略.....:NULL;" | $saveresult
(echo "[INFO]:密码有效期策略如下:" && more /etc/login.defs | grep -v "#" | grep PASS ) | $saveresult
echo ";" | $saveresult
printf "\n" | $saveresult

#2.密码有效期
passmax=$(cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}')
if [ $passmax -le 90 -a $passmax -gt 0 ];then
	echo "[INFO]:口令生存周期为${passmax}天,符合要求:NULL;" | $saveresult
else
	echo "[HIGH]:口令生存周期为${passmax}天,不符合要求,建议设置为0-90天:NULL;" | $saveresult | $savewarning
fi

#3.密码修改的最小时间间隔
passmin=$(cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}')
if [ $passmin -ge 6 ];then
	echo "[INFO]:口令更改最小时间间隔为${passmin}天,符合要求:NULL;" | $saveresult
else
	echo "[HIGH]:口令更改最小时间间隔为${passmin}天,不符合要求,建议设置不小于6天:NULL;" | $saveresult | $savewarning
fi

#4.密码过期的警告天数
passage=$(cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}')
if [ $passage -ge 30 -a $passage -lt $passmax ];then
	echo "[INFO]:口令过期警告时间天数为${passage},符合要求:NULL;" | $saveresult
else
	echo "[HIGH]:口令过期警告时间天数为${passage},不符合要求,建议设置大于等于30并小于口令生存周期:NULL;" | $saveresult ｜ $savewarning
fi
printf "\n" | $saveresult

#5.密码过期用户
echo "[OK]:正在检查密码已过期用户.....:NULL;" | $saveresult
NOW=$(date "+%s")
day=$((${NOW}/86400))
passwdexpired=$(grep -v ":[\!\*x]([\*\!])?:" /etc/shadow | awk -v today=${day} -F: '{ if (($5!="") && (today>$3+$5)) { print $1 }}')
if [ -n "$passwdexpired" ];then
	(echo "[MEDIUM]:以下用户的密码已过期:" && echo "$passwdexpired" && echo ";")  | $saveresult | $savewarning
else
	echo "[INFO]:未发现密码已过期用户:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------密码策略检查结束----------

#----------ssh配置检查----------
#1.ssh配置
echo "[OK]:正在检查sshd配置.....:NULL;" | $saveresult
sshdconfig=$(more /etc/ssh/sshd_config | egrep -v "#|^$")
if [ -n "$sshdconfig" ];then
	(echo "[INFO]:sshd配置文件如下:" && echo "$sshdconfig" && echo ";") | $saveresult
else
	echo "[INFO]:未发现sshd配置文件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.空口令登陆
echo "[OK]:正在检查是否允许空口令登录.....:NULL;" | $saveresult
emptypasswd=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
nopasswd=`gawk -F: '($2=="") {print $1}' /etc/shadow`
if [ -n "$emptypasswd" ];then
	echo "[HIGH]:允许空口令登录,请注意！！！:NULL;" | $savewarning | $saveresult
	if [ -n "$nopasswd" ];then
		(echo "[HIGH]:以下用户空口令:" && echo "$nopasswd" && echo ";") | $savewarning | $saveresult
	else
		echo "[HIGH]:但未发现空口令用户:NULL;" | $saveresult | $savewarning
	fi
else
	echo "[INFO]:不允许空口令用户登录:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.root远程登录
echo "[OK]:正在检查是否允许root远程登录.....:NULL;" | $saveresult
cat /etc/ssh/sshd_config | grep -v "^#" |grep "PermitRootLogin no"
if [ $? -eq 0 ];then
	echo "[INFO]:root不允许登陆,符合要求:NULL;" | $saveresult
else
	echo "[HIGH]:允许root远程登陆,不符合要求,建议/etc/ssh/sshd_config添加PermitRootLogin no:NULL;" | $saveresult | $savewarning
fi
printf "\n" | $saveresult

#----------文件相关检测----------
#1.24小时内变动文件
#查看最近24小时内有改变的文件
echo "[OK]:正在检查24小时内发生修改的文件.....:NULL;" | $saveresult
$modifyfile=$(find / -mtime 0 | grep -E "\.(py|sh|per|pl|php|asp|jsp)$")
if [ -n "$modifyfile" ];then
    (echo "[INFO]:24小时内如下文件发生修改:" && echo "$modifyfile" && echo ";")  | $saveresult
else
    echo "[INFO]:24小时内没有文件发生修改:NULL;" | $savewarning
fi
printf "\n" | $saveresult
#----------文件相关检测结束----------

#----------文件系统完整性检测----------
echo "[OK]:正在检测系统关键文件完整性.....:NULL;" | $saveresult
file="./checkrules/sysfile_md5.txt"
touch $tmp_file
if [ -e "$file" ]; then
    md5sum -c $file | awk -F: '$2!=" OK"{print $1}' | $savetmp
    if [ -s $tmp_file];then
        echo "[DANGER]:如下关键文件发生修改:" ｜ $savewarning | $saveresult
        for i in `cat $tmp_file`
        do
            echo $i | $savewarning | $saveresult
        done
        echo ";" | $saveresult | $savewarning
    else
        echo "[INFO]:系统关键文件未发生修改:NULL;" | $saveresult
    fi
else
	md5sum /usr/bin/awk >> $file
	md5sum /usr/bin/basename >> $file
	md5sum /usr/bin/bash >> $file
	md5sum /usr/bin/cat >> $file
	md5sum /usr/bin/chattr >> $file
	md5sum /usr/bin/chmod >> $file
	md5sum /usr/bin/chown >> $file
	md5sum /usr/bin/cp >> $file
	md5sum /usr/bin/curl >> $file
	md5sum /usr/bin/cut >> $file
	md5sum /usr/bin/date >> $file
	md5sum /usr/bin/df >> $file
	md5sum /usr/bin/diff >> $file
	md5sum /usr/bin/dirname >> $file
	md5sum /usr/bin/dmesg >> $file
	md5sum /usr/bin/du >> $file
	md5sum /usr/bin/echo >> $file
	md5sum /usr/bin/ed >> $file
	md5sum /usr/bin/egrep >> $file
	md5sum /usr/bin/env >> $file
	md5sum /usr/bin/fgrep >> $file
	md5sum /usr/bin/file >> $file
	md5sum /usr/bin/find >> $file
	md5sum /usr/bin/gawk >> $file
	md5sum /usr/bin/grep >> $file
	md5sum /usr/bin/groups >> $file
	md5sum /usr/bin/head >> $file
	md5sum /usr/bin/id >> $file
	md5sum /usr/bin/ipcs >> $file
	md5sum /usr/bin/kill >> $file
	md5sum /usr/bin/killall >> $file
	md5sum /usr/bin/kmod >> $file
	md5sum /usr/bin/last >> $file
	md5sum /usr/bin/lastlog >> $file
	md5sum /usr/bin/ldd >> $file
	md5sum /usr/bin/less >> $file
	md5sum /usr/bin/logger >> $file
	md5sum /usr/bin/login >> $file
	md5sum /usr/bin/ls >> $file
	md5sum /usr/bin/lsattr >> $file
	md5sum /usr/bin/md5sum >> $file
	md5sum /usr/bin/mktemp >> $file
	md5sum /usr/bin/more >> $file
	md5sum /usr/bin/mount >> $file
	md5sum /usr/bin/mv >> $file
	md5sum /usr/bin/netstat >> $file
	md5sum /usr/bin/newgrp >> $file
	md5sum /usr/bin/numfmt >> $file
	md5sum /usr/bin/passwd >> $file
	md5sum /usr/bin/perl >> $file
	md5sum /usr/bin/pgrep >> $file
	md5sum /usr/bin/ping >> $file
	md5sum /usr/bin/pkill >> $file
	md5sum /usr/bin/ps >> $file
	md5sum /usr/bin/pstree >> $file
	md5sum /usr/bin/pwd >> $file
	md5sum /usr/bin/readlink >> $file
	md5sum /usr/bin/runcon >> $file
	md5sum /usr/bin/sed >> $file
	md5sum /usr/bin/sh >> $file
	md5sum /usr/bin/sha1sum >> $file
	md5sum /usr/bin/sha224sum >> $file
	md5sum /usr/bin/sha256sum >> $file
	md5sum /usr/bin/sha384sum >> $file
	md5sum /usr/bin/sha512sum >> $file
	md5sum /usr/bin/size >> $file
	md5sum /usr/bin/sort >> $file
	md5sum /usr/bin/ssh >> $file
	md5sum /usr/bin/stat >> $file
	md5sum /usr/bin/strace >> $file
	md5sum /usr/bin/strings >> $file
	md5sum /usr/bin/su >> $file
	md5sum /usr/bin/sudo >> $file
	md5sum /usr/bin/systemctl >> $file
	md5sum /usr/bin/tail >> $file
	md5sum /usr/bin/test >> $file
	md5sum /usr/bin/top >> $file
	md5sum /usr/bin/touch >> $file
	md5sum /usr/bin/tr >> $file
	md5sum /usr/bin/uname >> $file
	md5sum /usr/bin/uniq >> $file
	md5sum /usr/bin/users >> $file
	md5sum /usr/bin/vmstat >> $file
	md5sum /usr/bin/w >> $file
	md5sum /usr/bin/watch >> $file
	md5sum /usr/bin/wc >> $file
	md5sum /usr/bin/wget >> $file
	md5sum /usr/bin/whatis >> $file
	md5sum /usr/bin/whereis >> $file
	md5sum /usr/bin/which >> $file
	md5sum /usr/bin/who >> $file
	md5sum /usr/bin/whoami >> $file
	md5sum /usr/sbin/adduser >> $file
	md5sum /usr/sbin/chroot >> $file
	md5sum /usr/sbin/depmod >> $file
	md5sum /usr/sbin/fsck >> $file
	md5sum /usr/sbin/groupadd >> $file
	md5sum /usr/sbin/groupdel >> $file
	md5sum /usr/sbin/groupmod >> $file
	md5sum /usr/sbin/grpck >> $file
	md5sum /usr/sbin/ifconfig >> $file
	md5sum /usr/sbin/ifdown >> $file
	md5sum /usr/sbin/ifup >> $file
	md5sum /usr/sbin/init >> $file
	md5sum /usr/sbin/insmod >> $file
	md5sum /usr/sbin/ip >> $file
	md5sum /usr/sbin/lsmod >> $file
	md5sum /usr/sbin/modinfo >> $file
	md5sum /usr/sbin/modprobe >> $file
	md5sum /usr/sbin/nologin >> $file
	md5sum /usr/sbin/pwck >> $file
	md5sum /usr/sbin/rmmod >> $file
	md5sum /usr/sbin/route >> $file
	md5sum /usr/sbin/rsyslogd >> $file
	md5sum /usr/sbin/runlevel >> $file
	md5sum /usr/sbin/sshd >> $file
	md5sum /usr/sbin/sulogin >> $file
	md5sum /usr/sbin/sysctl >> $file
	md5sum /usr/sbin/useradd >> $file
	md5sum /usr/sbin/userdel >> $file
	md5sum /usr/sbin/usermod >> $file
	md5sum /usr/sbin/vipw >> $file
fi
echo "[INFO]:系统关键文件未发生修改:NULL;" | $saveresult
printf "\n" | $saveresult
rm -f $tmp_file
#----------文件系统完整性检测结束----------

#----------日志分析----------
#1.系统日志是否被清除
echo "[OK]:正在分析日志文件是否存在.....:NULL;" | $saveresult
logs=$(ls -l /var/log/)
if [ -n "$logs" ];then
	echo "[INFO]:日志文件存在:NULL;" | $saveresult
else
	echo "[DANGER]:日志文件不存在,请分析是否被清除:NULL;" | $savewarning | $saveresult
fi
printf "\n" | $saveresult

#2.apt日志分析
#2.1.软件下载情况
echo "[OK]:正在分析使用apt下载软件情况.....:NULL;" | $saveresult
apt_install=$(more /var/log/apt/history.log | grep Install |awk -F: '{for(i=2;i<=NF;++i) printf $i"*";print "\n"}' | awk -F'\\),' '{for(i=1;i<=NF;++i) printf $i"\n"}' | awk -F* '{print $1}' | sort | uniq)
if [ -n "$apt_install" ];then
	(echo "[INFO]:曾使用apt下载以下软件:"  && echo "$apt_install" && echo ";") | $saveresult
else
	echo "[INFO]:未使用apt下载过软件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.2.软件卸载情况
echo "[OK]:正在检查使用apt卸载软件情况.....:NULL;" | $saveresult
apt_purge=$(more /var/log/apt/history.log | grep Purge | awk -F: '{for(i=2;i<=NF;++i) printf $i"*";print "\n"}' | awk -F'\\),' '{for(i=1;i<=NF;++i) printf $i"\n"     }' | awk -F* '{print $1}' | sort | uniq)
if [ -n "$apt_purge" ];then
	(echo "[INFO]:使用apt曾卸载以下软件:" && echo "$apt_purge" && echo ";")  | $saveresult
else
	echo "[INFO]:未使用apt卸载过软件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.3 可疑工具下载
echo "[OK]:正在检查使用apt安装的可疑工具.....:NULL;" | $saveresult
hacker_tools=$(more /var/log/apt/history.log | grep Install |awk -F: '{for(i=2;i<=NF;++i) printf $i"*";print "\n"}' | awk -F'\\),' '{for(i=1;i<=NF;++i) printf $i"\n"}' | awk -F* '{print $1}' | sort | uniq| grep -E "(^nc|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)")
if [ -n "$hacker_tools" ];then
	(echo "[DANGER]:发现使用apt下载过以下可疑软件:" && echo "$hacker_tools" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现使用apt下载过可疑软件:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.lastlog日志分析
echo "[OK]:正在分析所有用户最后一次登录日志.....:NULL;" | $saveresult
lastlog=$(lastlog)
if [ -n "$lastlog" ];then
	(echo "[INFO]:所有用户最后一次登录日志如下:" && echo "$lastlog" && echo ";") | $saveresult
else
	echo "[INFO]:未发现所有用户最后一次登录日志:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------日志分析结束----------

#----------内核检查----------
#1.内核情况
echo "[OK]:正在检查内核信息......:NULL;" | $saveresult
lsmod=$(lsmod)
if [ -n "$lsmod" ];then
	(echo "[INFO]:内核信息如下:" && echo "$lsmod" && echo ";") | $saveresult
else
	echo "[INFO]:未发现内核信息:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.可疑内核
echo "[INFO]:正在检查可疑内核.....:NULL;" | $saveresult
danger_lsmod=$(lsmod | grep -Ev "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state")
if [ -n "$danger_lsmod" ];then
	(echo "[HIGH]:发现可疑内核模块:" && echo "$danger_lsmod" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:未发现可疑内核模块:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------内核检查结束----------

#----------系统性能分析----------
#1.磁盘分析
#1.1.磁盘使用情况
echo "[OK]:正在检查磁盘使用.....:NULL;" | $saveresult
echo "[INFO]:磁盘使用情况如下:" && df -h  && echo ";"| $saveresult
printf "\n" | $saveresult

#1.2.磁盘使用过大
echo "[OK]:正在检查磁盘使用是否过大.....:NULL;" | $saveresult
#使用超过70%告警
df=$(df -h | awk 'NR!=1{print $1,$5}' | awk -F% '{print $1}' | awk '{if ($2>70) print $1,$2}')
if [ -n "$df" ];then
	(echo "[HIGH]:硬盘空间使用过高，请注意！！！" && echo "$df" && echo ";") | $savewarning | $saveresult
else
	echo "[INFO]:硬盘空间足够:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#2.CPU分析
#2.1.CPU使用情况
echo "[OK]:正在检查CPU相关信息.....:NULL;" | $saveresult
(echo "[INFO]:CPU硬件信息如下:" && more /proc/cpuinfo && echo ";") | $saveresult
(echo "[INFO]:CPU使用情况如下:" && ps -aux | sort -nr -k 3 | awk  '{print $1,$2,$3,$NF}') | $saveresult
echo ";" | $saveresult
printf "\n" | $saveresult

#2.2.CPU占用前5的进程
echo "[OK]:正在检查占用CPU前5资源的进程.....:NULL;" | $saveresult
(echo "[HIGH]:占用CPU资源前5进程：" && ps -aux | sort -nr -k 3 | head -5)  | $saveresult | $savewarning
echo ";" | $saveresult | $savewarning
printf "\n" | $saveresult

#2.3.CPU占用较大的进程
echo "[OK]:正在检查占用CPU较大的进程.....:NULL;" | $saveresult
pscpu=$(ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=20) print $0}')
if [ -n "$pscpu" ];then
	echo "[HIGH]:以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
	echo "$pscpu" | tee -a 20.2.3_pscpu.txt | $savewarning | $saveresult
    echo ";" | $savewarning | $saveresult
else
	echo "[INFO]:未发现进程占用资源超过20%:NULL;" | $saveresult
fi
printf "\n" | $saveresult

#3.内存分析
#3.1.内存情况
echo "[OK]:正在检查内存相关信息.....:NULL;" | $saveresult
(echo "[INFO]:内存信息如下:" && more /proc/meminfo && echo ";") | $saveresult
(echo "[INFO]:内存使用情况如下:" && free -m && echo ";") | $saveresult
printf "\n" | $saveresult

#3.2.占用内存前5的进程
echo "[OK]:正在检查占用内存前5资源的进程.....:NULL;" | $saveresult
(echo "[HIGH]:占用内存资源前5进程：" && ps -aux | sort -nr -k 4 | head -5) | $saveresult | $savewarning
echo ";" | $saveresult | $savewarning
printf "\n" | $saveresult

#3.3.占用内存较多的进程
echo "[OK]:正在检查占用内存较多的进程.....:NULL;" | $saveresult
psmem=$(ps -aux | sort -nr -k 4 | head -5 | awk '{if($4>=2) print $0}')
if [ -n "$psmem" ];then
	echo "[HIGH]:以下进程占用的内存超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
	echo "$psmem" | tee -a $danger_file | $saveresult
    echo ";" | $saveresult | $savewarning
else
	echo "[INFO]:未发现进程占用内存资源超过20%:NULL;" | $saveresult
fi
printf "\n" | $saveresult
#----------系统性能分析结束----------

#----------恶意文件扫描----------
echo "[OK]:正在扫描恶意文件..........:NULL;" | $saveresult
clamscan -ri $targetfilepath &> ./clam.log
num=$(cat clam.log | grep "Infected" | awk -F: '{print $2}')
if [ "$num" -eq 0 ];then
    echo "[INFO]:未发现恶意文件:NULL;" | $saveresult 
else
    InfectedFile=$(head -n $num clam.log| awk -F: '{print $1}')
    echo "[DANGER]:检测到恶意文件:" | $saveresult | $savewarning
    echo "$InfectedFile" | $saveresult | $savewarning
    echo ";" | $saveresult | $savewarning
fi
#----------恶意文件扫描结束----------

#----------清理工作痕迹----------
rubbish=$(ls | grep -Ev "1_result.log|1_warning.log|clam.log|checkrules|linuxcheck.sh|hosts.txt|put.exp|config.conf")
rm -rf $rubbish
#----------清理工作痕迹结束----------

#----------上传结果----------

#若要开启开功能取消下面注释的内容

hostaddr=`cat hosts.txt`
isupload=`echo $hostaddr | awk -F "[:]" '{print $1}'`
ipadd=`echo $hostaddr | awk -F "[:]" '{print $2}'`
port=`echo $hostaddr | awk -F "[:]" '{print $3}'`
username=`echo $hostaddr | awk -F "[:]" '{print $4}'`
userpasswd=`echo $hostaddr | awk -F "[:]" '{print $5}'`
#rootpasswd=`echo $i | awk -F "[:]" '{print $6}'`
if [ "$isupload" -eq 1 ];then
    expect put.exp $ipadd $port $username $userpasswd
fi
#----------上传完毕----------

#echo "[OK]:正在将检查文件压缩到/tmp/目录下......"
#zip -r /tmp/buying_${ipadd}_${date}.zip /tmp/buying_${ipadd}_${date}/*
#tar -zcvf /tmp/${ipadd}_${date}.tar.gz /tmp/${ipadd}_${date}/*

echo "检查结束！！！"
