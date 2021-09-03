#sudo simple_switch --interface 0@ens5 --interface 1@ens4 $1.bmv2/$1.json &
sudo simple_switch --interface 0@ens5 --interface 1@ens4 --log-console $1.bmv2/$1.json >> mri_switch.log &
