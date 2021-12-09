sed -i '$a measure fowner=0' /etc/ima/ima-policy
read -p "The ima policy has been written in the file,please restart your device now[y/n] " input
case $input in
        [yY]*)
                reboot
                ;;
        [nN]*)
                exit
                ;;
        *)
                echo "Just enter y or n, please."
                exit
                ;;
esac

