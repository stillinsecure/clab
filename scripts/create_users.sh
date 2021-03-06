#!/bin/bash

user_names=($(shuf -n 10 user_names.txt))
ip_addresses=($(hostname -i))

for index in {0..9}
do
    user_name=${user_names[$index]}
    useradd --create-home $user_name
    password=$(cat /dev/urandom | tr -dc A-Za-z0-9 | head -c16)
    usermod --password $password $user_name
    echo "$(hostname), ${ip_addresses[0]}, $user_name, $password" >> $1
done
