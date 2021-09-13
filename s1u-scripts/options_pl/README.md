gtp.p4 file adds an  additional header "ipv4 options" to transfer packet count
of a flow towards switch sgi. At sgi-switch the header is  dropped  but its
information is used for computing packet loss on intermediate link 
